package web

import (
	"context"
	"io"
	"net/http"
	"time"

	clientcore "github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/coder/websocket"
)

func (s *Service) shellSocket(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeErr(w, http.StatusBadRequest, "远程命令行只能连一直在线的机器")
		return
	}
	b, err := s.clientBridge()
	if err != nil {
		rpcErr(w, err)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	b.mu.Lock()
	err = b.selectTarget(sessionID, "", "implant")
	b.mu.Unlock()
	if err != nil {
		_ = conn.Write(ctx, websocket.MessageText, []byte(err.Error()))
		return
	}

	tunnel, err := openShell(ctx, b, sessionID)
	if err != nil {
		_ = conn.Write(ctx, websocket.MessageText, []byte(err.Error()+"\n"))
		return
	}
	defer func() {
		clientcore.GetTunnels().CloseIf(tunnel)
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_, _ = b.con.Rpc.CloseTunnel(closeCtx, &sliverpb.Tunnel{TunnelID: tunnel.ID, SessionID: tunnel.SessionID})
	}()

	_ = conn.Write(ctx, websocket.MessageText, []byte("远程命令行已连上。输入命令后回车，关掉这个面板就会断开。\n"))
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := tunnel.Read(buf)
			if n > 0 {
				if writeErr := conn.Write(ctx, websocket.MessageBinary, append([]byte(nil), buf[:n]...)); writeErr != nil {
					errCh <- writeErr
					return
				}
			}
			if readErr != nil {
				errCh <- readErr
				return
			}
		}
	}()
	go func() {
		for {
			_, data, readErr := conn.Read(ctx)
			if readErr != nil {
				errCh <- readErr
				return
			}
			if _, writeErr := tunnel.Write(data); writeErr != nil {
				errCh <- writeErr
				return
			}
		}
	}()
	<-errCh
}

func openShell(ctx context.Context, b *bridge, sessionID string) (*clientcore.TunnelIO, error) {
	rpcTunnel, err := b.con.Rpc.CreateTunnel(ctx, &sliverpb.Tunnel{SessionID: sessionID})
	if err != nil {
		return nil, err
	}
	tunnel := clientcore.GetTunnels().Start(rpcTunnel.TunnelID, rpcTunnel.SessionID)
	select {
	case <-tunnel.Bound():
	case <-tunnel.Done():
		return nil, io.EOF
	case <-time.After(8 * time.Second):
		return nil, context.DeadlineExceeded
	}
	shell, err := b.con.Rpc.Shell(ctx, &sliverpb.ShellReq{
		Request:   b.con.ActiveTarget.Request(nil),
		EnablePTY: true,
		Rows:      40,
		Cols:      120,
		TunnelID:  tunnel.ID,
	})
	if err != nil {
		return nil, err
	}
	if shell.GetResponse() != nil && shell.Response.Err != "" {
		return nil, errString(shell.Response.Err)
	}
	return tunnel, nil
}
