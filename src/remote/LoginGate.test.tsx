//! Regression coverage for the WS-handshake rate-limit path (FIX: every E2EE handshake failure was
//! shown as an expired-link/wrong-password terminal screen): a `rate_limited` reason returns to the
//! password form with the same login.rateLimited message the HTTP-429 path uses, while credential
//! failures keep the terminal auth-failed guidance.

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { authLostCbs, pairingMode, session, wsClientMock } = vi.hoisted(() => {
  const authLostCbs = new Set<(reason?: "rate_limited" | "unauthorized") => void>();
  const pairingMode = { value: true };
  // Stateful token so the mode-check effect's getSessionToken sees the token the autologin stored,
  // exactly like the real wsClient.
  const session = { token: null as string | null };
  return {
    authLostCbs,
    pairingMode,
    session,
    wsClientMock: {
      isPairingMode: () => pairingMode.value,
      onAuthLost: (cb: (reason?: "rate_limited" | "unauthorized") => void) => {
        authLostCbs.add(cb);
        return () => authLostCbs.delete(cb);
      },
      getSessionToken: () => session.token,
      authHeaders: () => ({}),
      setSessionToken: vi.fn((tok: string) => {
        session.token = tok;
      }),
      setPairingPassword: vi.fn(),
      reconnectNow: vi.fn(),
    },
  };
});

vi.mock("../i18n", () => ({
  // Echo keys so assertions are locale-independent.
  useT: () => (key: string) => key,
}));
vi.mock("../ipc/transport", () => ({ isTauri: false }));
vi.mock("../ipc/reqLog", () => ({ recordRequestError: vi.fn() }));
vi.mock("../ipc/wsClient", () => ({ wsClient: wsClientMock }));

import { LoginGate } from "./LoginGate";

afterEach(() => {
  cleanup();
  authLostCbs.clear();
  pairingMode.value = true;
  session.token = null;
  delete (window as { __VLX_AUTOLOGIN__?: unknown }).__VLX_AUTOLOGIN__;
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const fireAuthLost = (reason?: "rate_limited" | "unauthorized") =>
  act(() => {
    for (const cb of authLostCbs) cb(reason);
  });

describe("LoginGate E2EE handshake failures", () => {
  it("shows the rate-limit message on the password form for a rate_limited handshake", () => {
    render(<LoginGate>app</LoginGate>);
    fireAuthLost("rate_limited");
    // Back on the login form (password input present) with the rate-limit explanation, not the
    // terminal expired-link screen and not a wrong-password message.
    expect(screen.getByPlaceholderText("login.passwordPlaceholder")).toBeTruthy();
    expect(screen.getByText("login.rateLimited")).toBeTruthy();
    expect(screen.queryByText("login.authFailed")).toBeNull();
  });

  it("keeps the terminal auth-failed guidance for credential failures", () => {
    render(<LoginGate>app</LoginGate>);
    fireAuthLost("unauthorized");
    expect(screen.getByText("login.authFailed")).toBeTruthy();
    expect(screen.queryByPlaceholderText("login.passwordPlaceholder")).toBeNull();
  });

  it("treats a missing reason as a credential failure (decrypt failure path)", () => {
    render(<LoginGate>app</LoginGate>);
    fireAuthLost();
    expect(screen.getByText("login.authFailed")).toBeTruthy();
  });
});

describe("LoginGate non-pairing (token) mode on rate_limited", () => {
  // Pins the CURRENT behavior of the token-session branch: a rate_limited handshake reason is not
  // treated specially there — with a known password the gate immediately fires the next silent
  // relogin against /api/login, spending another attempt of the very budget that was just exhausted.
  // If that behavior is ever changed (e.g. backoff on rate_limited), this test must change with it.
  it("fires an immediate silent relogin even when the reason is rate_limited", async () => {
    pairingMode.value = false;
    (window as { __VLX_AUTOLOGIN__?: { password: string } }).__VLX_AUTOLOGIN__ = {
      password: "pw",
    };
    const loginCalls: string[] = [];
    const fetchMock = vi.fn((url: string) => {
      if (url === "/api/mode") {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ requirePairing: false }) });
      }
      if (url === "/api/me") {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
      }
      if (url === "/api/login") {
        loginCalls.push(url);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ token: "tok" }) });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({}) });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<LoginGate>app</LoginGate>);
    // Autologin performs the first /api/login and mounts the app.
    await waitFor(() => expect(loginCalls.length).toBe(1));
    await screen.findByText("app");

    fireAuthLost("rate_limited");
    // Current behavior under pin: the rate-limit reason does not suppress or delay the silent
    // relogin — a second /api/login fires immediately and, on success, the client reconnects.
    await waitFor(() => expect(loginCalls.length).toBe(2));
    await waitFor(() => expect(wsClientMock.reconnectNow).toHaveBeenCalled());
  });
});
