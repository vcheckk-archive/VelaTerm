//! Regression coverage for restart persistence in the remote-access panel: the port field prefills the
//! last persisted port instead of the hardcoded 8799, and a failed auto-start surfaces its error message.

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WebServerStatus } from "../../ipc/webServer";

const { webServerStatus, webDevicesList, webPairingCreate } = vi.hoisted(() => ({
  webServerStatus: vi.fn(),
  webDevicesList: vi.fn(async () => []),
  webPairingCreate: vi.fn(async () => ({ url: "https://x/#pair=abc", deviceToken: "t" })),
}));

vi.mock("../../i18n", () => ({
  // Echo keys so assertions are locale-independent.
  useT: () => (key: string) => key,
}));
vi.mock("../../ipc/webServer", () => ({
  webServerStatus,
  webDevicesList,
  webPairingCreate,
  webServerStart: vi.fn(),
  webServerStop: vi.fn(),
  webDeviceRevoke: vi.fn(),
}));
vi.mock("../../ipc/info", () => ({ copyText: vi.fn() }));
// The real Backdrop pulls in native-view suspension hooks irrelevant to this test.
vi.mock("../../components/Backdrop", () => ({
  Backdrop: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

import { RemoteAccessPanel } from "./RemoteAccessPanel";

/** Stopped-service status with the given persisted extras. */
function stoppedStatus(extra: Partial<WebServerStatus>): WebServerStatus {
  return {
    running: false,
    port: null,
    url: null,
    urls: [],
    fingerprint: null,
    autostartError: null,
    savedPort: null,
    autoStart: false,
    ...extra,
  };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("RemoteAccessPanel restart persistence", () => {
  it("prefills the port field with the persisted savedPort instead of 8799", async () => {
    webServerStatus.mockResolvedValue(stoppedStatus({ savedPort: 9123 }));
    render(<RemoteAccessPanel onClose={() => {}} />);
    await waitFor(() => {
      const input = screen.getByPlaceholderText("8799") as HTMLInputElement;
      expect(input.value).toBe("9123");
    });
  });

  it("keeps the 8799 default when no port was persisted", async () => {
    webServerStatus.mockResolvedValue(stoppedStatus({}));
    render(<RemoteAccessPanel onClose={() => {}} />);
    await waitFor(() => {
      const input = screen.getByPlaceholderText("8799") as HTMLInputElement;
      expect(input.value).toBe("8799");
    });
  });

  it("shows the auto-start error reported by the backend", async () => {
    webServerStatus.mockResolvedValue(
      stoppedStatus({ autostartError: "Port 9123 is already in use" }),
    );
    render(<RemoteAccessPanel onClose={() => {}} />);
    await waitFor(() => {
      expect(
        screen.getByText(/remote\.autostartFailed Port 9123 is already in use/),
      ).toBeTruthy();
    });
  });
});
