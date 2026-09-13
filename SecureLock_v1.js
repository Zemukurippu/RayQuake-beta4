
window.eewRunning = true;

/* ============================================================
   SecureLock_option
   ============================================================ */

let runningCheckEnabled   = false; // ブートチェック
let hashCheckEnabled      = false; // ハッシュ整合性チェック
let schemaCheckEnabled    = false; // スキーマ検証
let crossCheckEnabled     = false; // データ整合性チェック
let domCheckEnabled       = false; // DOM チェック
let variableCheckEnabled  = false; // 変数改ざんチェック
let functionCheckEnabled  = false; // 関数改ざんチェック
let eventCheckEnabled     = false; // イベント改ざんチェック


/* ============================================================
   SecureLock_v1
   ============================================================ */

   document.addEventListener("DOMContentLoaded", () => {

  const makeToggle = (id, flagName, label) => {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.addEventListener("click", () => {
      window[flagName] = !window[flagName];
      btn.textContent = `${label}：${window[flagName] ? "オン" : "オフ"}`;
      console.warn(`SecureLock: ${label} is now ${window[flagName] ? "ENABLED" : "DISABLED"}`);
    });
  };

  makeToggle("hashToggleBtn",     "hashCheckEnabled",     "ハッシュ整合性チェック");
  makeToggle("schemaToggleBtn",   "schemaCheckEnabled",   "スキーマ検証");
  makeToggle("crossToggleBtn",    "crossCheckEnabled",    "データ整合性チェック");
  makeToggle("domToggleBtn",      "domCheckEnabled",      "DOM チェック");
  makeToggle("variableToggleBtn", "variableCheckEnabled", "変数改ざんチェック");
  makeToggle("functionToggleBtn", "functionCheckEnabled", "関数改ざんチェック");
  makeToggle("eventToggleBtn",    "eventCheckEnabled",    "イベント改ざんチェック");

});


/* ============================================================
   HC(HashCheck) — 起動後2秒遅延で誤検知防止
   ============================================================ */

function integrityCheck() {
  const expectedHash =
    "9de2bc5b209167a0b74e65dfb30a27872159f4cb5eb48dec743fb46f08790e679dbbbde59398aada005f27d4d3ed74e3289e3067f9413b31da5c718feba8d53e";

  fetch("./SecureLock_v1.js")
    .then((r) => r.text())
    .then(async (text) => {
      const buf = await crypto.subtle.digest(
        "SHA-512",
        new TextEncoder().encode(text)
      );
      const hash = [...new Uint8Array(buf)]
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("");

      if (hashCheckEnabled && hash !== expectedHash) {
        RQsys_stopAll("SecureLock_v1.js tampered");
      }
    })
    .catch(() => {
      RQsys_stopAll("SecureLock_v1.js integrity check failed");
    });
}

setTimeout(integrityCheck, 2000);

/* ============================================================
   secure+ blockB (MainDefender)
   ============================================================ */

let secureState = {
  tamperDetected: false,
  lastWolfx: null,
  lastP2P: null,
  lockTester: true,
  stop: false
};

/* 全停止処理 */
function RQsys_stopAll(reason = "Unknown") {
  console.warn("SecureLock STOP:", reason);
  secureState.stop = true;

  try {
    window.eewRunning = false;
    const log = document.getElementById("log");
    if (log) {
      log.innerHTML = "";
      log.scrollTop = 0;
    }

    document.body.innerHTML = `
      <h1 style="text-align:left; margin-top:240px;">
        異常を検出したため、システムを緊急停止しました。
      </h1>
      <p style="margin-left:20px;">StopCode: ${reason}</p>
    `;
  } catch (e) {
    console.error("RQsys_stopAll error:", e);
  }
}

/* ============================================================
   スキーマ検証
   ============================================================ */

function validateSchema(type, data) {
  if (secureState.stop) return false;
  if (!schemaCheckEnabled) return true; // OFFなら常に通す

  const schema = type === "wolfx" ? wolfxSchema : p2pSchema;

  for (const key of schema.required) {
    if (!(key in data)) {
      console.warn(`SecureLock: Missing key "${key}"`);
      return false;
    }
  }
  return true;
}

/* ============================================================
   データ整合性チェック
   ============================================================ */

function crossCheck(type, data) {
  if (secureState.stop) return false;
  if (!crossCheckEnabled) return true; // OFFなら常に通す

  if (type === "wolfx") {
    if (secureState.lastWolfx) {
      if (data.Serial < secureState.lastWolfx.Serial) {
        console.warn("SecureLock: Wolfx Serial regression");
        return false;
      }
    }
    secureState.lastWolfx = data;
  }

  if (type === "p2p") {
    if (secureState.lastP2P) {
      if (data.id === secureState.lastP2P.id) {
        console.warn("SecureLock: Duplicate P2P ID (許可)");
      }
    }
    secureState.lastP2P = data;
  }

  return true;
}

/* ============================================================
   SecureValidate
   ============================================================ */

window.secureValidate = function (type, raw) {
  if (secureState.stop) return false;
  if (!window.eewRunning) {
    console.warn("SecureLock: eewRunning=false → 停止中");
    return false;
  }

  if (!validateSchema(type, raw)) {
    RQsys_stopAll("Schema validation failed (" + type + ")");
    return false;
  }

  if (!crossCheck(type, raw)) {
    RQsys_stopAll("Cross-check failed (" + type + ")");
    return false;
  }

  return true;
};

/* ============================================================
   管理者テストツールのロック解除
   ============================================================ */

window.unlockEEWTester = function () {
  if (secureState.stop) return;

  const input = document.getElementById("eewTesterPassword");
  const error = document.getElementById("eewTesterError");
  const content = document.getElementById("eewTesterContent");

  if (!input || !error || !content) return;

  const pass = input.value.trim();
  if (pass === "RayQuakeAdmin2026") {
    secureState.lockTester = false;
    content.style.display = "block";
    error.style.display = "none";
  } else {
    error.style.display = "block";
  }
};

/* ============================================================
   テスト送信の保護
   ============================================================ */

window.sendTestEEW = function () {
  if (secureState.stop) return;
  if (secureState.lockTester) {
    alert("管理者ロック中です。解除してください。");
    return;
  }
  alert("テストEEW送信（SecureLock保護下）");
};

window.startTest = function () {
  if (secureState.stop) return;
  if (secureState.lockTester) {
    alert("管理者ロック中です。解除してください。");
    return;
  }
  alert("テストマップ送信（SecureLock保護下）");
};

/* ============================================================
   DOM チェック
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
  const requiredIds = ["eewTesterLock", "eewTesterContent"];

  setTimeout(() => {
    setInterval(() => {
      if (secureState.stop) return;

      for (const id of requiredIds) {
        const el = document.getElementById(id);
        if (domCheckEnabled && !el) {
          RQsys_stopAll("DOM tampered: missing " + id);
          return;
        }
      }
    }, 1500);
  }, 2000);
});

/* ============================================================
   変数改ざんチェック
   ============================================================ */

(function variableTamperCheck() {
  let last = { lockTester: secureState.lockTester };

  setInterval(() => {
    if (secureState.stop) return;

    if (variableCheckEnabled && secureState.lockTester !== last.lockTester) {
      RQsys_stopAll("Variable tampered: lockTester");
    }
  }, 500);
})();

/* ============================================================
   関数改ざんチェック
   ============================================================ */

(function functionTamperCheck() {
  const originalStopAll = RQsys_stopAll.toString();
  const originalValidate = secureValidate.toString();

  setInterval(() => {
    if (secureState.stop) return;

    if (functionCheckEnabled && RQsys_stopAll.toString() !== originalStopAll) {
      RQsys_stopAll("Function tampered: RQsys_stopAll");
    }
    if (functionCheckEnabled && secureValidate.toString() !== originalValidate) {
      RQsys_stopAll("Function tampered: secureValidate");
    }
  }, 800);
})();

/* ============================================================
   イベント改ざんチェック
   ============================================================ */

(function eventTamperCheck() {
  const tester = document.getElementById("eewTesterPassword");
  if (!tester) return;

  const original = tester.oninput;

  setInterval(() => {
    if (secureState.stop) return;

    if (eventCheckEnabled && tester.oninput !== original) {
      RQsys_stopAll("Event tampered: eewTesterPassword");
    }
  }, 1000);
})();
