export interface AxilBridge {
  mount(): void;
  destroy(): void;
  makeImports(): {
    ws_connect(url_ptr: number, url_len: number): void;
    ws_send(buf_ptr: number, buf_len: number): void;
    axil_ws_send(buf_ptr: number, buf_len: number): void;
    ws_send_channel(channel: number, buf_ptr: number, buf_len: number): void;
    ws_status(): number;
    ws_close(): void;
  };
}

export declare function createAxilBridge(root?: any, getWasm?: () => any): AxilBridge;
