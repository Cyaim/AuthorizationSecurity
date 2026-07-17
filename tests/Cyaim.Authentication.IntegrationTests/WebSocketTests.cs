using System;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// WebSocket 握手鉴权：查询字符串令牌、无令牌拒绝、无权限拒绝、回显消息。
    /// </summary>
    public class WebSocketTests : IAsyncLifetime
    {
        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        [Fact]
        public async Task Alice_WithWsPermission_HandshakeSucceeds_AndEchoes()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "alice", "alice123");
            WebSocketClient wsClient = _app.Server.CreateWebSocketClient();

            using WebSocket ws = await wsClient.ConnectAsync(
                new Uri($"ws://localhost/t/ws?access_token={Uri.EscapeDataString(token)}"),
                CancellationToken.None);

            byte[] message = Encoding.UTF8.GetBytes("hello-ws");
            await ws.SendAsync(new ArraySegment<byte>(message), WebSocketMessageType.Text, true, CancellationToken.None);

            byte[] buffer = new byte[4096];
            WebSocketReceiveResult result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
            Assert.Equal(WebSocketMessageType.Text, result.MessageType);
            Assert.Equal("hello-ws", Encoding.UTF8.GetString(buffer, 0, result.Count));

            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
        }

        [Fact]
        public async Task NoToken_HandshakeFails()
        {
            WebSocketClient wsClient = _app.Server.CreateWebSocketClient();

            await Assert.ThrowsAnyAsync<Exception>(() =>
                wsClient.ConnectAsync(new Uri("ws://localhost/t/ws"), CancellationToken.None));
        }

        [Fact]
        public async Task Bob_WithoutWsPermission_HandshakeFails()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");
            WebSocketClient wsClient = _app.Server.CreateWebSocketClient();

            await Assert.ThrowsAnyAsync<Exception>(() =>
                wsClient.ConnectAsync(
                    new Uri($"ws://localhost/t/ws?access_token={Uri.EscapeDataString(token)}"),
                    CancellationToken.None));
        }
    }
}
