//! Coverage for the advertised-IP selector: choosing an IP persists it and regenerates the pairing
//! link with exactly that address, a vanished persisted IP falls back to automatic, and the URL
//! ordering helper matches hosts exactly instead of by substring.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const {
  invokeMock,
  networkInterfacesListMock,
  webPairingCreateMock,
  webServerStatusMock,
  appSettings,
} = vi.hoisted(() => {
  const appSettings: Record<string, string> = {};
  return {
    appSettings,
    invokeMock: vi.fn((cmd: string, args?: { entries?: Record<string, string> }) => {
      if (cmd === "get_app_settings") return Promise.resolve({ ...appSettings });
      if (cmd === "set_app_settings") {
        Object.assign(appSettings, args?.entries ?? {});
        return Promise.resolve(null);
      }
      return Promise.reject(new Error(`unexpected invoke: ${cmd}`));
    }),
    networkInterfacesListMock: vi.fn(),
    webPairingCreateMock: vi.fn(),
    webServerStatusMock: vi.fn(),
  };
});

vi.mock("../../i18n", () => ({
  useT: () => (key: string) => key,
}));
vi.mock("../../ipc/transport", () => ({ invoke: invokeMock }));
vi.mock("../../ipc/info", () => ({ copyText: vi.fn() }));
// The backdrop shell pulls in platform hooks irrelevant here; render children directly.
vi.mock("../../components/Backdrop", () => ({
  Backdrop: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
// Stub the QR renderer to expose its value prop, so tests can assert the QR encodes exactly the
// pairing URL for the chosen host (AC 3: link AND QR) instead of inferring it from the copy button.
vi.mock("qrcode.react", () => ({
  QRCodeSVG: ({ value }: { value: string }) => <svg data-qr-value={value} />,
}));
vi.mock("../../ipc/webServer", () => ({
  networkInterfacesList: networkInterfacesListMock,
  webServerStatus: webServerStatusMock,
  webServerStart: vi.fn(),
  webServerStop: vi.fn(),
  webPairingCreate: webPairingCreateMock,
  webDevicesList: vi.fn().mockResolvedValue([]),
  webDeviceRevoke: vi.fn(),
}));

import { orderUrlsBySelectedIp, RemoteAccessPanel } from "./RemoteAccessPanel";

const LAN_URL = "https://192.168.1.5:8799";
const CGNAT_URL = "https://100.100.83.2:8799";

/** Running LanTls-like status listing a LAN URL first and the CGNAT (Tailscale) URL last. */
function runningStatus() {
  return {
    running: true,
    port: 8799,
    url: LAN_URL,
    urls: [LAN_URL, CGNAT_URL],
    fingerprint: null,
  };
}

function mockDefaults() {
  webServerStatusMock.mockResolvedValue(runningStatus());
  networkInterfacesListMock.mockResolvedValue([
    { name: "en0", ip: "192.168.1.5", vpn: false },
    { name: "utun3", ip: "100.100.83.2", vpn: true },
  ]);
  webPairingCreateMock.mockImplementation((address?: string) =>
    Promise.resolve({
      url: `${address ? `https://${address}:8799` : LAN_URL}/#pair=tok`,
      deviceToken: "device-token",
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  for (const key of Object.keys(appSettings)) delete appSettings[key];
});

describe("advertised-IP selector", () => {
  it("lists Automatic plus all interfaces and drives persistence, pairing link, and primary URL", async () => {
    mockDefaults();
    render(<RemoteAccessPanel onClose={vi.fn()} />);

    // The stopped-state selector is replaced by the running-state one once the status arrives, so
    // re-query until the running selector carries all options.
    await waitFor(() => {
      const sel = screen.getByRole("combobox", { name: "remote.ipLabel" }) as HTMLSelectElement;
      expect(sel.options.length).toBe(3);
    });
    const select = screen.getByRole("combobox", {
      name: "remote.ipLabel",
    }) as HTMLSelectElement;
    // Automatic plus both interfaces, with the interface name and the VPN mark visible.
    const labels = Array.from(select.options).map((o) => o.textContent);
    expect(labels[0]).toBe("remote.ipAuto");
    expect(labels).toContain("192.168.1.5 · en0");
    expect(labels).toContain("100.100.83.2 · utun3 (remote.ipVpn)");

    // The automatic pairing on open passes no address.
    await waitFor(() =>
      expect(webPairingCreateMock).toHaveBeenCalledWith(undefined, false),
    );

    fireEvent.change(select, { target: { value: "100.100.83.2" } });

    // Selection is persisted under the share-IP key and regenerates the link with exactly that address.
    expect(invokeMock).toHaveBeenCalledWith("set_app_settings", {
      entries: { "vlx-share-ip": "100.100.83.2" },
    });
    await waitFor(() =>
      expect(webPairingCreateMock).toHaveBeenCalledWith("100.100.83.2", false),
    );

    // The primary displayed/copied pairing URL carries the chosen host.
    await waitFor(() => {
      const copyButtons = screen.getAllByTitle("remote.copyUrl");
      expect(copyButtons[0].textContent).toContain("https://100.100.83.2:8799/#pair=tok");
    });

    // AC 3 explicitly: the QR encodes the pairing URL for the chosen host, not just the copy button.
    await waitFor(() => {
      const qr = document.querySelector("[data-qr-value]");
      expect(qr?.getAttribute("data-qr-value")).toBe("https://100.100.83.2:8799/#pair=tok");
    });
  });

  it("restores a persisted, present IP on open and drives the pairing link with it", async () => {
    mockDefaults();
    appSettings["vlx-share-ip"] = "100.100.83.2";
    render(<RemoteAccessPanel onClose={vi.fn()} />);

    // The restored setting shows in the selector once interfaces and settings have arrived.
    await waitFor(() => {
      const sel = screen.getByRole("combobox", { name: "remote.ipLabel" }) as HTMLSelectElement;
      expect(sel.options.length).toBe(3);
      expect(sel.value).toBe("100.100.83.2");
    });

    // The setting may arrive after the automatic pairing; the regeneration effect must then re-pair
    // with the restored address (timing-sensitive path: pairUrl guard in RemoteAccessPanel).
    await waitFor(() =>
      expect(webPairingCreateMock).toHaveBeenCalledWith("100.100.83.2", false),
    );

    // The primary displayed/copied URL carries the restored host.
    await waitFor(() => {
      const copyButtons = screen.getAllByTitle("remote.copyUrl");
      expect(copyButtons[0].textContent).toContain("https://100.100.83.2:8799/#pair=tok");
    });
  });

  it("falls back to Automatic when the persisted IP is absent, without erasing the stored value", async () => {
    mockDefaults();
    appSettings["vlx-share-ip"] = "10.9.9.9"; // e.g. a VPN interface that is currently down
    render(<RemoteAccessPanel onClose={vi.fn()} />);

    // Wait for the running-state selector with the full option list, then check the shown value.
    await waitFor(() => {
      const sel = screen.getByRole("combobox", { name: "remote.ipLabel" }) as HTMLSelectElement;
      expect(sel.options.length).toBe(3);
      expect(sel.value).toBe("");
    });

    // Pairing uses the automatic backend default; no call ever passes the vanished address.
    await waitFor(() =>
      expect(webPairingCreateMock).toHaveBeenCalledWith(undefined, false),
    );
    expect(webPairingCreateMock).not.toHaveBeenCalledWith("10.9.9.9", false);

    // The stored value is untouched; only an explicit re-selection would overwrite it.
    expect(appSettings["vlx-share-ip"]).toBe("10.9.9.9");
  });
});

describe("orderUrlsBySelectedIp", () => {
  it("moves the selected IP's URL to the front and keeps backend order otherwise", () => {
    expect(orderUrlsBySelectedIp([LAN_URL, CGNAT_URL], "100.100.83.2")).toEqual([
      CGNAT_URL,
      LAN_URL,
    ]);
  });

  it("leaves order unchanged for automatic or an absent IP", () => {
    expect(orderUrlsBySelectedIp([LAN_URL, CGNAT_URL], "")).toEqual([LAN_URL, CGNAT_URL]);
    expect(orderUrlsBySelectedIp([LAN_URL, CGNAT_URL], "10.9.9.9")).toEqual([
      LAN_URL,
      CGNAT_URL,
    ]);
  });

  it("matches the host exactly, never by substring", () => {
    const urls = ["https://10.0.0.11:8799", "https://10.0.0.1:8799"];
    expect(orderUrlsBySelectedIp(urls, "10.0.0.1")).toEqual([
      "https://10.0.0.1:8799",
      "https://10.0.0.11:8799",
    ]);
  });
});
