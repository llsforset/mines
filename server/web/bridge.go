package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/client/command"
	clientconsole "github.com/bishopfox/sliver/client/console"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/kballard/go-shellquote"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const grpcMessageLimit = (2 << 30) - 1

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

type commandFlag struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand"`
	Usage     string `json:"usage"`
	Type      string `json:"type"`
	Default   string `json:"default"`
}

type commandSpec struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Path   []string      `json:"path"`
	Use    string        `json:"use"`
	Short  string        `json:"short"`
	Group  string        `json:"group"`
	Hidden bool          `json:"hidden"`
	Flags  []commandFlag `json:"flags"`
}

type bridge struct {
	con    *clientconsole.SliverClient
	server *cobra.Command
	sliver *cobra.Command
	mu     sync.Mutex
}

func (s *Service) commands(menu string) ([]commandSpec, error) {
	b, err := s.clientBridge()
	if err != nil {
		return nil, err
	}
	root := b.server
	if menu == "implant" {
		root = b.sliver
	}
	var specs []commandSpec
	collectCommands(root, nil, &specs)
	return specs, nil
}

func (s *Service) execCommand(menu, sessionID, beaconID string, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("缺少命令")
	}
	b, err := s.clientBridge()
	if err != nil {
		return "", err
	}
	line := shellquote.Join(args...)
	if reason := blockedInteractive(args); reason != "" {
		return "", fmt.Errorf("%s", reason)
	}
	timeout := 3 * time.Minute
	switch args[0] {
	case "generate", "regenerate", "stage", "profiles":
		timeout = 15 * time.Minute
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.selectTarget(sessionID, beaconID, menu); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	b.con.SetOutput(&lockedWriter{w: &buf})
	defer b.con.SetOutput(nil)

	done := make(chan error, 1)
	go func() {
		done <- b.con.RunLine(line)
	}()
	select {
	case err := <-done:
		output := cleanOutput(buf.String())
		if err != nil {
			return output, err
		}
		return output, nil
	case <-time.After(timeout):
		return cleanOutput(buf.String()), fmt.Errorf("命令超过 %s 仍未返回", timeout)
	}
}

func (b *bridge) selectTarget(sessionID, beaconID, menu string) error {
	if menu != "implant" || (sessionID == "" && beaconID == "") {
		b.con.ActiveTarget.Set(nil, nil)
		b.con.App.SwitchMenu(consts.ServerMenu)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if sessionID != "" {
		sessions, err := b.con.Rpc.GetSessions(ctx, &commonpb.Empty{})
		if err != nil {
			return err
		}
		for _, session := range sessions.GetSessions() {
			if session.GetID() == sessionID {
				b.con.ActiveTarget.Set(session, nil)
				b.con.App.SwitchMenu(consts.ImplantMenu)
				return nil
			}
		}
		return fmt.Errorf("找不到 session %s", sessionID)
	}
	beacons, err := b.con.Rpc.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		return err
	}
	for _, beacon := range beacons.GetBeacons() {
		if beacon.GetID() == beaconID {
			b.con.ActiveTarget.Set(nil, beacon)
			b.con.App.SwitchMenu(consts.ImplantMenu)
			return nil
		}
	}
	return fmt.Errorf("找不到 beacon %s", beaconID)
}

func (s *Service) clientBridge() (*bridge, error) {
	s.bridgeOnce.Do(func() {
		s.bridge, s.bridgeErr = newBridge(s.rpc)
	})
	return s.bridge, s.bridgeErr
}

func newBridge(server rpcServer) (*bridge, error) {
	listener := bufconn.Listen(32 << 20)
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcMessageLimit),
		grpc.MaxSendMsgSize(grpcMessageLimit),
	)
	rpcpb.RegisterSliverRPCServer(grpcServer, server)
	go grpcServer.Serve(listener)

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(grpcMessageLimit), grpc.MaxCallSendMsgSize(grpcMessageLimit)),
	)
	if err != nil {
		return nil, err
	}
	con := clientconsole.NewConsole(true)
	if con.Settings != nil {
		con.Settings.AutoAdult = true
	}
	rootServer := command.ServerCommands(con, nil)()
	rootSliver := command.SliverCommands(con)()
	err = clientconsole.StartClient(con, rpcpb.NewSliverRPCClient(conn), conn, nil,
		func() *cobra.Command { return rootServer },
		func() *cobra.Command { return rootSliver },
		false, "")
	if err != nil {
		return nil, err
	}
	return &bridge{con: con, server: rootServer, sliver: rootSliver}, nil
}

type rpcServer interface {
	rpcpb.SliverRPCServer
}

func collectCommands(cmd *cobra.Command, parent []string, out *[]commandSpec) {
	for _, child := range cmd.Commands() {
		name := child.Name()
		if name == "help" || name == "completion" || strings.HasPrefix(name, "_") {
			continue
		}
		path := append(append([]string{}, parent...), name)
		if child.Runnable() {
			*out = append(*out, commandSpec{
				ID:     strings.Join(path, " "),
				Name:   name,
				Path:   path,
				Use:    child.Use,
				Short:  child.Short,
				Group:  groupName(child),
				Hidden: child.Hidden,
				Flags:  flagsOf(child),
			})
		}
		collectCommands(child, path, out)
	}
}

func groupName(cmd *cobra.Command) string {
	if cmd.GroupID != "" {
		return cmd.GroupID
	}
	return "其他"
}

func flagsOf(cmd *cobra.Command) []commandFlag {
	var flags []commandFlag
	seen := map[string]bool{}
	add := func(flag *pflag.Flag) {
		if flag.Name == "help" || flag.Hidden || seen[flag.Name] {
			return
		}
		seen[flag.Name] = true
		flags = append(flags, commandFlag{
			Name:      flag.Name,
			Shorthand: flag.Shorthand,
			Usage:     flag.Usage,
			Type:      flag.Value.Type(),
			Default:   flag.DefValue,
		})
	}
	cmd.LocalFlags().VisitAll(add)
	cmd.InheritedFlags().VisitAll(add)
	return flags
}

func blockedInteractive(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "shell":
		if len(args) == 1 || args[1] == "attach" {
			return "远程命令行会占住这个页面。请先打开一个目标，再进「终端」页。这里可以执行 shell ls 和 shell kill。"
		}
	case "edit", "hexedit":
		return "这个命令会打开电脑上的全屏编辑器。网页里请改用查看文件、下载和上传。"
	case "ai":
		return "AI 对话要来回说话，这个输入框装不下。"
	case "crack":
		if len(args) > 1 && args[1] == "top" {
			return "这是电脑上的全屏进度画面。网页里请看破解任务列表。"
		}
	}
	return ""
}

func cleanOutput(text string) string {
	text = ansiPattern.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, "\r", "")
	return strings.TrimSpace(text)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
