// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as k from "./newkeys.js";

const prod = true;
const keep = 3;
(async (main) => {
  console.log("gen keys for prod!");
  try {
    await k.saveRsaKey();
    await k.savePskSvc();

    await k.setRsaWranglerSecrets(prod);
    await k.deleteOlderRsaWranglerSecrets(prod, keep);
    await k.setPskWranglerSecret(prod);
  } catch (ex) {
    console.error(ex);
    process.exit(1);
  }
})();
