// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors
import * as k from "./newkeys.js";

const notprod = false;

(async (main) => {
  console.log("gen keys for dev...");
  try {
    await k.saveRsaKey();
    await k.savePskSvc();

    await k.setRsaWranglerSecrets(notprod);
    await k.deleteOlderRsaWranglerSecrets(notprod, maxkeys);
    await k.setPskWranglerSecret(notprod);
  } catch (ex) {
    console.error(ex);
    process.exit(1);
  }
})();
