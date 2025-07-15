package handlers

import (
	"context"
	"fmt"

	"github.com/gorilla/mux"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var whoamiHandler server.ToolHandlerFunc = func(ctx context.Context, request mcp.CallToolRequest) (res *mcp.CallToolResult, err error) {
	name := ctx.Value(ContextKeyName)
	email := ctx.Value(ContextKeyEmail)
	res = mcp.NewToolResultText(fmt.Sprintf("Hello, %s! Your email is %s.", name, email))

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

func (h *MCPHandler) RegisterRoutes(app *mux.Router) {
	app.Handle("", server.NewStreamableHTTPServer(h.mcpServer))
}
