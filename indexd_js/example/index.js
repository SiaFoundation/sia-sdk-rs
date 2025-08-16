import { get_host_settings } from 'indexd_sdk';

(async function() {
  const settings = await get_host_settings("6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984");
  document.body.innerHTML = `
    <h1>Host Settings</h1>
    <pre>${JSON.stringify(settings, null, 2)}</pre>
  `;
})()