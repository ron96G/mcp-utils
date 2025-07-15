package handlers

import (
	"context"
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var whoamiHandler server.ToolHandlerFunc = func(ctx context.Context, request mcp.CallToolRequest) (res *mcp.CallToolResult, err error) {
	name := ctx.Value(ContextKeyName).(string)
	email := ctx.Value(ContextKeyEmail).(string)
	readOnly := ctx.Value(ContextKeyReadOnly).(bool)
	allowedAction := "read"
	if !readOnly {
		allowedAction = "write"
	}
	msg := fmt.Sprintf("Hello, %s! Your email is %s and you are allowed to %s", name, email, allowedAction)
	res = mcp.NewToolResultText(msg)
	return res, nil
}

type MCPHandler struct {
	mcpServer *server.MCPServer
}

func NewMCPHandler() *MCPHandler {
	mcpHandler := &MCPHandler{}
	mcpHandler.mcpServer = server.NewMCPServer(
		"Demo 🚀",
		"0.0.1",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	whoamiTool := mcp.NewTool("whoami",
		mcp.WithDescription("Get the name of the authenticated user"),
	)

	mcpHandler.mcpServer.AddTool(whoamiTool, whoamiHandler)
	return mcpHandler
}

func (h *MCPHandler) RegisterRoutes(app chi.Router) {
	app.Handle("/mcp", server.NewStreamableHTTPServer(h.mcpServer))
}
