export type StreamSubscriber = (bytes: Uint8Array, isText: boolean) => void;

export interface AxilClientOptions {
  url?: string;
  autoConnect?: boolean;
}

export declare class AxilClient {
  url: string | null;
  status: number;
  constructor(options?: AxilClientOptions);
  connect(url?: string): void;
  send(data: string | Uint8Array | ArrayBuffer): boolean;
  sendChannel(channel: number, data: string | Uint8Array | ArrayBuffer): boolean;
  subscribe(cb: StreamSubscriber): () => boolean;
  subscribeChannel(channel: number, cb: StreamSubscriber): () => boolean;
  close(): void;
}

export { createAxilBridge, AxilBridge } from "./bridge.js";
