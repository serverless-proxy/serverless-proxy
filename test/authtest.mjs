// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as hmac from "../src/webcrypto/hmac.js";
import * as bin from "../src/base/buf.js";
import * as brsa from "../src/sjcl/brsa.js";
import * as auth from "../src/core/auth.js";
import * as log from "../src/base/log.js";
import * as krsa from "../src/webcrypto/blindrsa.js";

const enc = new TextEncoder();
// ref: github.com/privacypass/challenge-bypass-extension/blob/732205c052d/src/blindrsa/blindrsa.test.ts
(async (main) => {
  log.key("d");
  await gointerop();
  await tokenauth();
  await blindrsa();
})();

async function tokenauth() {
  const seed = bin.buf2hex(hmac.rand(32));
  const ctx = "test";
  const sk = await auth.keygen(seed, ctx);
  const token = bin.str2byte("fullthex");
  const thex = bin.buf2hex(token);
  const hashedtoken = await hmac.sha256(token);
  const hashedthex = bin.buf2hex(hashedtoken);

  const claim = await auth.issue(sk, hashedthex);
  const fullthex = claim[0] + thex;

  console.log("fullthex:", fullthex, "\nhashedthex:", claim[0] + hashedthex);

  const sighex = claim[1];
  const msg = bin.str2byte("msg");
  const msghex = bin.buf2hex(msg);
  const msgmachex = await auth.message(sighex, msghex);
  const y = await auth.verifyClaim(sk, fullthex, msghex, msgmachex);
  console.log("tokenauth: verifyClaim:", y == auth.ok);
}

async function genrsakey() {
  const x = await krsa.genkey();
  const w = await krsa.importkey(x[0], x[1]);
  console.log(JSON.stringify(x[0]));
  console.log(JSON.stringify(x[1]));
  return w;
}

async function gointerop() {
  const pkjwkstr =
    '{"kty":"RSA","alg":"PS384","n":"vRJS-stmaRwFsgmbtugnZLPcGz-80gnbYdCuhju4CwbuGeQk2JI1Qkivcy50TFgO5z7jz38ighp_Hr2kvOOEWvo_l_J_Ix3mpw9RBDZF6ocNRYuoS9R_SoeMgrx-VQWC1VSqqbbT7A5526an4Kmsrnes1MyroK052CT4QYPUT_wbICmv85uqEuyD7q6X-HpHvHBTiTRQtcfxHJUrXebInCU6cg1VtcJsDoYczRVL1i9_7z5POMyjAx1v-sSR_16r6H1NLghR6fpUwm-HmbKSPwqrN5NA8Q-94spj4zp_4PoAEQi2NRnjJSQQxPBeH8RRAfdO7HwnhDm7hXXgocTj_w","e":"AQAB","key_ops":["verify"],"ext":true}';
  const skjwkstr =
    '{"kty":"RSA","alg":"PS384","n":"vRJS-stmaRwFsgmbtugnZLPcGz-80gnbYdCuhju4CwbuGeQk2JI1Qkivcy50TFgO5z7jz38ighp_Hr2kvOOEWvo_l_J_Ix3mpw9RBDZF6ocNRYuoS9R_SoeMgrx-VQWC1VSqqbbT7A5526an4Kmsrnes1MyroK052CT4QYPUT_wbICmv85uqEuyD7q6X-HpHvHBTiTRQtcfxHJUrXebInCU6cg1VtcJsDoYczRVL1i9_7z5POMyjAx1v-sSR_16r6H1NLghR6fpUwm-HmbKSPwqrN5NA8Q-94spj4zp_4PoAEQi2NRnjJSQQxPBeH8RRAfdO7HwnhDm7hXXgocTj_w","e":"AQAB","d":"bc3vjSGFh3OzxxMXcOFgx3ZBVT3t_hmlZChawzB5kUXkD_tUfsZi0ez-oCkRd6kIdroqeb4_H0oeG49N1jlYC7IcLrWxqoZaBxm5FnYiorLuPT5_bhKqHnGcY-zufZgmxJhYSRoZ95TspmkiRDKmS-jK4gc_gaA44NOPrhTOv-gNcI5u15vAr0Ei2KWD4v86f-F1u44xy2-kEOtoHBr6PrFhp7cPKrO0byNIwfIElXSa3Ws347cpPeawU33XnNtMmNz0rdZMsjbZravILIjXgwhTV1hg9WIg6l6Dq6U6iEI8owoW-EqSr3oVy5zRnR2lGKj4IzSU-g4BWWyunJFY0Q","p":"1FDqhuHh3zoepa22olf4SLYdey-D9iimynt1n4vyijIdaoOnuWEFdth9AlCm6u3EYQYX9HkQQxsM6bjo1Bwh8rQzeBkj34mS5b2thor1cGxgXjYVC7DPW2rf06VkFB5ELl9yPVFhuYGPw5ekuXPs7ZTi2pW71U3Akgo3PmHV2tc","q":"4_kTrIJjxWDp42Fn53jRDrj5cDsnM1j_7XYBj68lbdQKz0jucHxLe1mCt8C-DT1LCsXWaBnBwzIqdWMapJz6PzTGk6AIwdI371_65poWwaC7b65Jd5CNnG_V3EPUx1GnWGoeYO3Fa3rayeE9bfm6K0Suzhp-l89DIr7qSff-Axk","dp":"ByWKH2wvDDKKoY0NXr2TT-9BYsogqQKJSruJJAuz6E7ziohP9v97DZsP6ioI1FOYjqOD3ujMUVXxw1REEg-4XNEQAnTmLjoVRcJyutqmlFgxjjpHzxLuh-c7DYa9raevJ9hyofnBTls8GZtbIhry2LRwRmdP4UgyuTe60FC-wBU","dq":"c8lgCrA3CFrOsCQa59_fHoEof64rnNLJOcxDwryMYBngW6OJJyyaEc5GrBmC7aqB4LjWywy58vAZzIFHWPA50bx2VyhjCj5BFp1DC7ibckC2smRtAAM1SY0rq7Hv8kQwoKFVSJm7OXmugfaagq7htXQu7JNcVLJ6QL2CtYr1QpE","qi":"dUR-9jxBR70IqvWvhM3hZMi5n02HD1kUTp-MG04l0txGrGOB6_1VgFWxlyDWQfeSDLocWoc4W0VZX638BmhkJKdpAId7LbwprRzZopgzH6F1PAxzXPFBFwDU90mQ2fZ8j4rgQMJshvvf207Tqxm0tMzmnwr06_W7mqxTiiisJmk","key_ops":["sign"],"ext":true}';
  const ck = await krsa.importkey(skjwkstr, pkjwkstr);
  let blindmsghex =
    "6d65ff115c3805cc0466219179e02f6910add8d865e6bdb9e99eeeb842e82640e38fe20667e2a04ea8705eac04f399605857e72a5e922f9a59ead6bab43208211826ebf72f2dff447c645eae35a1f04d2108d1ba96b658fc453ec331a8628d8057896809e53ff9bf8f35230a268a543ef575ef82996dd1320cca3bb8b87d20141b0321ff184c0df0ecb5a1c52da74f67220479cef71e32430bd42aceb52ae279d90dcbf74abc79a5bfcf7892d7828f2df4af6ccf7255b7461640312729f8bb0cc843f2663b1eae77e72cad7d2b9e0b808a7f58b0d1e1d83906ed161f24a39990b65a273838892ae66013633195e5c8b103b7a6032b5b70a403ebb6ebb342d436";
  // blindmsghex =
  //  "53a59e7971eddaa6a88603bacc03dadeef847870efe7bfe7f147ebfed89b8869b0ac7cdfb30c8f86da5cabe55f5372f085ad3e7d688a3e9f8756bc905eed8fa15feb562d072e760147ca2f7828a204c6bb26fda696ec3ee1b640fa6bdd706b30bd904c73807164dcb4f14f6171af97ad04e30d8e9d50f69d8ab812a45a66cf0a9f4e2e999847c8d38fdb30f8c60b3fc2ea2f36206726c18fd62fabbbf6d61642e47a57b04ec4a54102b892ca130393fc4dd2bd17a0a9c7f9bf235ee76bafb78db29d8a3f5adcd2d3d2f251026b9869fec27f067efb96b4fbeee86bcfa1f1e9949737013291ab9db35e1cc020f659b0a4a70bfa2328267cff732d736805df9bc";

  const bmsg = bin.hex2buf(blindmsghex);
  const bsig = await brsa.blindSign(ck[0], bmsg);
  const bsighex = bin.buf2hex(bsig);
  console.log("bsig:", bsighex);
}

async function blindrsa() {
  const msg = enc.encode("rsa-pss test");
  // generate the private key for rsa-pss
  const [priv, pub] = await genrsakey();
  // const privjwk = await crypto.subtle.exportKey("jwk", ck.privateKey);
  // console.log("privjwk:", privjwk.d, privjwk.n);
  const hid = await brsa.blind(pub, msg, 16);
  const bmsg = hid.blindedMsg;
  const binv = hid.blindInv;
  const hid1 = await brsa.blind(pub, msg, 16);
  const bmsg1 = hid1.blindedMsg;
  const binv1 = hid1.blindInv;
  // const hid2 = await brsa.blind(pub, msg, 0);
  // const bmsg2 = hid2.blindedMsg;
  // const binv2 = hid2.blindInv;
  const hid3 = await brsa.blind(pub, msg, 16);
  const bmsg3 = hid3.blindedMsg;
  const binv3 = hid3.blindInv;
  // console.log("bmsg12", bin.buf2hex(bmsg), bin.buf2hex(bmsg1));
  // console.log("bmsg34", bin.buf2hex(bmsg2), bin.buf2hex(bmsg3));
  const bsig = await brsa.blindSign(priv, bmsg);
  const ok = await brsa.finalize(pub, msg, binv, bsig);
  const bsig1 = await brsa.blindSign(priv, bmsg1);
  const ok1 = await brsa.finalize(pub, msg, binv1, bsig1);
  const bsig3 = await brsa.blindSign(priv, bmsg3);
  const ok3 = await brsa.finalize(pub, msg, binv3, bsig3);

  console.log("ok", !bin.emptyBuf(ok));
  console.log("ok1", !bin.emptyBuf(ok1));
  console.log("ok3", !bin.emptyBuf(ok3));
}
