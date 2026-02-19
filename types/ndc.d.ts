/**
 * @tty-pt/ndc - WebSocket Terminal Client
 * TypeScript definitions for ndc.js
 */

import { Terminal } from '@xterm/xterm';

/**
 * Subscription object with hooks for terminal events
 */
export interface NdcSubscription {
  /**
   * Called on WebSocket message events
   * @param ev - WebSocket message event
   * @param arr - Message data as Uint8Array
   * @returns true to continue default processing, false to skip
   */
  onMessage: (ev: MessageEvent, arr: Uint8Array) => boolean;
  
  /**
   * Called when WebSocket connection opens
   * @param term - xterm.js Terminal instance
   * @param ws - WebSocket instance
   */
  onOpen: (term: Terminal, ws: WebSocket) => void;
  
  /**
   * Called when WebSocket connection closes
   * @param ws - WebSocket instance
   */
  onClose: (ws: WebSocket) => void;
  
  /**
   * Terminal columns
   */
  cols: number;
  
  /**
   * Terminal rows
   */
  rows: number;
  
  /**
   * Reconnection timeout handle (internal)
   */
  timeout?: number;
}

/**
 * Options for creating a terminal instance
 */
export interface NdcOptions {
  /**
   * WebSocket protocol to use
   * @default "wss" for HTTPS, "ws" for HTTP
   */
  proto?: 'ws' | 'wss';
  
  /**
   * Port number for WebSocket connection
   * @default window.location.port
   */
  port?: number | string;
  
  /**
   * Full WebSocket URL
   * @default "{proto}://{hostname}:{port}"
   */
  url?: string;
  
  /**
   * Subscription object with event hooks
   */
  sub?: Partial<NdcSubscription>;
  
  /**
   * Enable debug logging to console
   * @default false
   */
  debug?: boolean;
}

/**
 * Create and initialize a WebSocket terminal
 * 
 * @param element - DOM element to attach terminal to
 * @param options - Configuration options
 * @returns Subscription object with event hooks
 * 
 * @example
 * ```typescript
 * import { create } from "@tty-pt/ndc";
 * 
 * const term = create(document.getElementById("terminal"), {
 *   port: 4201,
 *   proto: "ws",
 *   sub: {
 *     onOpen: (term, ws) => console.log("Connected"),
 *     onClose: (ws) => console.log("Disconnected"),
 *     onMessage: (ev, arr) => true,
 *   }
 * });
 * ```
 */
export function create(element: HTMLElement, options?: NdcOptions): NdcSubscription;

/**
 * Global namespace attached to window
 */
export interface TtyNdc {
  create: typeof create;
}

declare global {
  interface Window {
    ttyNdc: TtyNdc;
  }
}

export default {
  create,
};
