const net = require('net');

function getHostAndPort(urlValue) {
  const parsedUrl = new URL(urlValue);
  return {
    host: parsedUrl.hostname,
    port: Number(parsedUrl.port)
  };
}

function canConnect({ host, port }, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    const finish = (isConnected) => {
      socket.destroy();
      resolve(isConnected);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function checkService(name, urlValue) {
  const target = getHostAndPort(urlValue);
  const isReachable = await canConnect(target);

  return {
    name,
    url: urlValue,
    host: target.host,
    port: target.port,
    isReachable
  };
}

module.exports = { checkService };
