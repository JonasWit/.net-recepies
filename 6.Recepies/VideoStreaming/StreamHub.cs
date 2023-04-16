using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.SignalR;
using System.Collections.Generic;
using System.IO;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace VideoStreaming;

public class StreamHub : Hub
{
    private readonly IWebHostEnvironment _env;

    public StreamHub(IWebHostEnvironment env) => _env = env;

    public readonly struct VideoData
    {
        public int Index { get; }
        public string Part { get; }
        public string UserName { get; }

        [JsonConstructor]
        public VideoData(int index, string part, string userName) => (Index, Part, UserName) = (index, part, userName);
    }

    public async Task SendVideoData(IAsyncEnumerable<VideoData> videoData)
    {
        await foreach (var d in videoData)
        {
            await Clients.Others.SendAsync("video-data", d);
        }
    }

    public async Task Send()
    {
        var c = 0;
        while (c < 6)
        {
            var bytes = GetFile(c++ % 3);
            await Clients.All.SendAsync("video-data", bytes);
            await Task.Delay(4000);
        }
    }

    public byte[] GetFile(int index)
    {
        var path = Path.Combine(_env.WebRootPath, $"vid{index}.webm");
        return File.ReadAllBytes(path);
    }
}