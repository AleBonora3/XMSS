const DATA_PATH = "../merkle.json";

const state = {
  data: null,
  step: 0,
  maxStep: 0,
  rootKey: null,
  playing: false,
  timer: null,
};

const elements = {
  svg: document.getElementById("tree"),
  rootStatus: document.getElementById("root-status"),
  params: document.getElementById("params"),
  play: document.getElementById("play"),
  stepBack: document.getElementById("step-back"),
  step: document.getElementById("step"),
  speed: document.getElementById("speed"),
  stepRange: document.getElementById("stepRange"),
  nodeDetails: document.getElementById("node-details"),
  publicParams: document.getElementById("public-params"),
  demoDetails: document.getElementById("demo-details"),
  demoSelect: document.getElementById("demo-select"),
  legendFormulas: document.getElementById("legend-formulas"),
  stepDetails: document.getElementById("step-details"),
};

const nodeMap = new Map();
const tableBody = document.querySelector("#tests-table tbody");

function setStatus(demo) {
  elements.rootStatus.textContent = `root_match: ${demo.root_match}`;
  elements.params.textContent = `params: n=${demo.params.n}, w=${demo.params.w}, h=${demo.params.h}, target_idx=${demo.target_idx}`;
}

function buildSvg(demo) {
  const levels = demo.tree.levels;
  const leafCount = levels[0].nodes.length;
  const maxLevel = levels.length - 1;

  const spacingX = 60;
  const spacingY = 80;
  const margin = 40;
  const width = margin * 2 + (leafCount - 1) * spacingX;
  const height = margin * 2 + maxLevel * spacingY;

  elements.svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  elements.svg.innerHTML = "";
  nodeMap.clear();

  const edgesGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
  const nodesGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");

  function xFor(level, index) {
    const span = Math.pow(2, level);
    const center = (index * span) + (span / 2) - 0.5;
    return margin + center * spacingX;
  }

  function yFor(level) {
    return margin + (maxLevel - level) * spacingY;
  }

  // Edges
  for (let level = 1; level <= maxLevel; level++) {
    const nodes = levels[level].nodes;
    for (let i = 0; i < nodes.length; i++) {
      const parentX = xFor(level, i);
      const parentY = yFor(level);
      const leftX = xFor(level - 1, i * 2);
      const rightX = xFor(level - 1, i * 2 + 1);
      const childY = yFor(level - 1);

      [leftX, rightX].forEach((cx) => {
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", parentX);
        line.setAttribute("y1", parentY);
        line.setAttribute("x2", cx);
        line.setAttribute("y2", childY);
        line.setAttribute("class", "edge");
        edgesGroup.appendChild(line);
      });
    }
  }

  // Nodes
  for (let level = 0; level <= maxLevel; level++) {
    const nodes = levels[level].nodes;
    for (let i = 0; i < nodes.length; i++) {
      const cx = xFor(level, i);
      const cy = yFor(level);

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", cx);
      circle.setAttribute("cy", cy);
      circle.setAttribute("r", 12);
      circle.setAttribute("class", "node other");
      circle.style.setProperty("--delay", `${(level * 40) + (i * 10)}ms`);
      circle.dataset.level = String(level);
      circle.dataset.index = String(i);
      if (level === maxLevel && i === 0) {
        circle.dataset.root = "true";
      }

      circle.addEventListener("click", () => showNodeDetails(demo, level, i));

      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
      label.setAttribute("x", cx);
      label.setAttribute("y", cy + 4);
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("class", "label");
      label.textContent = `${level}:${i}`;

      nodesGroup.appendChild(circle);
      nodesGroup.appendChild(label);

      nodeMap.set(`${level}:${i}`, circle);
    }
  }

  elements.svg.appendChild(edgesGroup);
  elements.svg.appendChild(nodesGroup);
}

function showNodeDetails(demo, level, index) {
  const nodes = demo.tree.levels[level].nodes;
  const entry = nodes[index];
  if (!entry) {
    elements.nodeDetails.textContent = "Nodo non trovato.";
    return;
  }

  const lines = [];
  if (demo.msg) {
    lines.push(`msg: ${demo.msg}`);
  }
  if (demo.mp) {
    lines.push(`mp: ${demo.mp}`);
  }
  lines.push(`Nodo selezionato: level=${level}, index=${index}`);
  if (entry.value) lines.push(`value: ${entry.value}`);
  if (entry.key) lines.push(`key: ${entry.key}`);
  if (entry.bm0) lines.push(`bm0: ${entry.bm0}`);
  if (entry.bm1) lines.push(`bm1: ${entry.bm1}`);
  if (entry.masked_left) lines.push(`masked_left: ${entry.masked_left}`);
  if (entry.masked_right) lines.push(`masked_right: ${entry.masked_right}`);

  if (entry.value) {
    lines.push("");
    if (level === 0) {
      lines.push("value: hash foglia (L-tree della WOTS PK)");
    } else {
      lines.push("value: hash del nodo interno del Merkle tree");
    }
  }

  if (level === 0) {
    lines.push("");
    lines.push(`Nodo foglia scelto: ${index}`);
    lines.push("")
    if (index !== demo.target_idx) {
      lines.push("Auth path disponibile solo per target_idx nel JSON.");
    } else {
      lines.push("Auth path:");
      let cur = index;
      for (let k = 0; k < demo.auth_path.length; k++) {
        const sibling = demo.auth_path[k];
        const parentIndex = Math.floor(cur / 2);
        const parent = demo.tree.levels[k + 1].nodes[parentIndex];
        lines.push(
          `- livello ${k}: sibling index=${sibling.sibling_index}`
        );
        lines.push(`  value=${sibling.sibling_value}`);
        lines.push("");
        if (parent) {
          lines.push(`  parent index=${parentIndex}`);
          lines.push(`  key=${parent.key}`);
          lines.push(`  bm0=${parent.bm0}`);
          lines.push(`  bm1=${parent.bm1}`);
          lines.push(`  masked_left=${parent.masked_left}`);
          lines.push(`  masked_right=${parent.masked_right}`);
          lines.push("");
          lines.push("");
        }
        cur = parentIndex;
      }
    }
  }

  elements.nodeDetails.textContent = lines.join("\n");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function applyStep(demo, step) {
  if (!demo || !demo.path || !demo.auth_path || !demo.tree) {
    elements.stepDetails.textContent = "Percorso non disponibile per questo test.";
    return;
  }
  const path = demo.path;
  const auth = demo.auth_path;

  nodeMap.forEach((node) => {
    node.classList.remove("path");
    node.classList.remove("sib");
    node.classList.add("other");
  });

  for (let i = 0; i <= step && i < path.length; i++) {
    const p = path[i];
    const key = `${p.level}:${p.node_index}`;
    const el = nodeMap.get(key);
    if (el) {
      el.classList.remove("other");
      el.classList.add("path");
    }

    const s = auth[i];
    const skey = `${s.level}:${s.sibling_index}`;
    const sel = nodeMap.get(skey);
    if (sel) {
      sel.classList.remove("other");
      sel.classList.add("sib");
    }
  }

  const detail = [];
  const add = (line) => detail.push(escapeHtml(line));
  const addHtml = (line) => detail.push(line);
  if (path[step]) {
    const cur = path[step];
    const sib = auth[step];
    const parentIndex = Math.floor(cur.node_index / 2);
    const parent = demo.tree.levels[step + 1].nodes[parentIndex];
    const isLeft = (cur.node_index % 2) === 0;
    const leftValue = isLeft ? cur.node_value : sib.sibling_value;
    const rightValue = isLeft ? sib.sibling_value : cur.node_value;

    add(`step: ${step}`);
    add(`path node: level=${cur.level}, index=${cur.node_index}`);
    add(`sibling_expected: level=${sib.level}, index=${sib.sibling_index}`);
    if (demo.auth_path_used && demo.auth_path_used[step]) {
      const sibUsed = demo.auth_path_used[step];
      add(`sibling_used: level=${sibUsed.level}, index=${sibUsed.sibling_index}`);
      add(`sibling_match: ${sibUsed.sibling_value === sib.sibling_value}`);
    }
    add("");
    add("Calcolo nodo padre:");
    add("Formula: Node = H(KEY, (LEFT xor BM0) || (RIGHT xor BM1))");
    add("");
    add(`left = ${leftValue}`);
    add(`right = ${rightValue}`);
    add("");
    if (parent) {
      add(`key = ${parent.key}`);
      add(`bm0 = ${parent.bm0}`);
      add(`bm1 = ${parent.bm1}`);
      add(`masked_left = ${parent.masked_left}`);
      add(`masked_right = ${parent.masked_right}`);
      add(`parent_expected = ${parent.value}`);
      if (demo.auth_nodes && demo.auth_nodes[step]) {
        const authNode = demo.auth_nodes[step].value;
        add(`parent_from_auth = ${authNode}`);
        const parentMatch = authNode === parent.value;
        if (parentMatch) {
          addHtml('<span class="ok">parent_match = true</span>');
        } else {
          addHtml('<span class="bad">parent_match = false</span>');
        }
      }
    }
  }
  elements.stepDetails.innerHTML = detail.join("<br>");
  if (step >= state.maxStep) {
    elements.demoDetails.innerHTML = renderDemoDetails(demo).join("<br>");
  } else {
    elements.demoDetails.textContent = "Completa gli step per vedere l'esito demo.";
  }
  updateRootIndicator(demo, step);
}

function stepForward() {
  state.step = Math.min(state.step + 1, state.maxStep);
  elements.stepRange.value = String(state.step);
  applyStep(getCurrentDemo(), state.step);
}

function stepBackward() {
  state.step = Math.max(state.step - 1, 0);
  elements.stepRange.value = String(state.step);
  applyStep(getCurrentDemo(), state.step);
}

function play() {
  if (state.playing) return;
  state.playing = true;
  const speed = Number(elements.speed.value);
  state.timer = setInterval(() => {
    if (state.step >= state.maxStep) {
      pause();
      return;
    }
    stepForward();
  }, speed);
}

function pause() {
  state.playing = false;
  if (state.timer) {
    clearInterval(state.timer);
    state.timer = null;
  }
}

function wireControls() {
  elements.play.addEventListener("click", play);
  elements.stepBack.addEventListener("click", () => {
    pause();
    stepBackward();
  });
  elements.step.addEventListener("click", () => {
    pause();
    stepForward();
  });

  elements.speed.addEventListener("input", () => {
    if (state.playing) {
      pause();
      play();
    }
  });

  elements.stepRange.addEventListener("input", (e) => {
    pause();
    state.step = Number(e.target.value);
    applyStep(getCurrentDemo(), state.step);
  });
}

function renderDemoDetails(demo) {
  const lines = [];

  lines.push(`demo: ${demo.label}`);
  if (demo.note) {
    lines.push(`note: ${demo.note}`);
  }
  if (demo.msg) {
    lines.push(`msg: ${demo.msg}`);
  }
  lines.push(`verify: ${demo.verify}`);
  if (demo.error) {
    lines.push(`error: ${demo.error}`);
  }
  if (demo.mp) {
    lines.push(`mp: ${demo.mp}`);
  }
  if (demo.leaf_expected && demo.leaf_from_auth) {
    lines.push(`leaf_expected: ${demo.leaf_expected}`);
    lines.push(`leaf_from_auth: ${demo.leaf_from_auth}`);
    const leafMatch = demo.leaf_match ? "ok" : "bad";
    lines.push(`<span class="${leafMatch}">leaf_match: ${demo.leaf_match}</span>`);
    if (!demo.leaf_match) {
      const leafDiff = firstDiffIndex(demo.leaf_expected, demo.leaf_from_auth);
      if (leafDiff !== -1) {
        lines.push(`leaf_diff_at_byte: ${leafDiff}`);
      }
    }
  }
  if (demo.root_expected && demo.root_from_auth) {
    lines.push(`root_expected: ${demo.root_expected}`);
    lines.push(`root_from_auth: ${demo.root_from_auth}`);
    const rootMatchClass = demo.root_match ? "ok" : "bad";
    lines.push(`<span class="${rootMatchClass}">root_match: ${demo.root_match}</span>`);
    if (!demo.root_match) {
      lines.push("reason: root ricostruita diversa dalla root pubblica");
      const diff = firstDiffIndex(demo.root_expected, demo.root_from_auth);
      if (diff !== -1) {
        lines.push(`root_diff_at_byte: ${diff}`);
      }
    }
  }

  if (demo.idx_values) {
    lines.push(`idx_values: ${demo.idx_values.join(", ")}`);
  }
  if (demo.idx_monotonic !== undefined) {
    const idxClass = demo.idx_monotonic ? "ok" : "bad";
    lines.push(`<span class="${idxClass}">idx_monotonic: ${demo.idx_monotonic}</span>`);
  }
  if (demo.exhausted !== undefined) {
    const exClass = demo.exhausted ? "ok" : "bad";
    lines.push(`<span class="${exClass}">exhausted: ${demo.exhausted}</span>`);
  }
  if (demo.rollback_same_idx !== undefined) {
    lines.push(`rollback_idx: ${demo.rollback_idx}`);
    const rbClass = demo.rollback_same_idx ? "bad" : "ok";
    lines.push(`<span class="${rbClass}">rollback_same_idx: ${demo.rollback_same_idx}</span>`);
    if (demo.rollback_sig2_ok !== undefined) {
      lines.push(`rollback_sig2_ok: ${demo.rollback_sig2_ok}`);
    }
  }

  return lines;
}

function firstDiffIndex(hexA, hexB) {
  const len = Math.min(hexA.length, hexB.length);
  for (let i = 0; i < len; i++) {
    if (hexA[i] !== hexB[i]) {
      return Math.floor(i / 2);
    }
  }
  if (hexA.length !== hexB.length) {
    return Math.floor(len / 2);
  }
  return -1;
}

function updateRootIndicator(demo, step) {
  if (!state.rootKey) return;
  const rootNode = nodeMap.get(state.rootKey);
  if (!rootNode) return;

  rootNode.classList.remove("root-ok", "root-bad");

  if (step < state.maxStep) {
    return;
  }

  if (demo.root_match) {
    rootNode.classList.add("root-ok");
  } else {
    rootNode.classList.add("root-bad");
  }
}

function getCurrentDemo() {
  if (!state.data || !state.data.demos) return null;
  return state.data.demos[elements.demoSelect.value];
}

function applyDemo() {
  const demo = getCurrentDemo();
  if (!demo) {
    elements.demoDetails.textContent = "Demo non disponibile.";
    return;
  }
  if (!demo.tree || !demo.path || !demo.auth_path) {
    elements.svg.innerHTML = "";
    nodeMap.clear();
    elements.stepDetails.textContent = "Percorso non disponibile per questo test.";
    elements.publicParams.textContent = "";
    state.maxStep = 0;
    state.step = 0;
    elements.stepRange.max = "0";
    elements.stepRange.value = "0";
    elements.demoDetails.innerHTML = renderDemoDetails(demo).join("<br>");
    return;
  }

  state.maxStep = demo.path.length - 1;
  state.step = Math.min(state.step, state.maxStep);
  elements.stepRange.max = String(state.maxStep);
  elements.stepRange.value = String(state.step);
  state.rootKey = `${demo.tree.levels.length - 1}:0`;

  setStatus(demo);
  buildSvg(demo);
  applyStep(demo, state.step);
  showNodeDetails(demo, 0, demo.target_idx);
  elements.publicParams.textContent =
    `pub_seed: ${demo.pub_seed}\nroot: ${demo.root}\nparams: n=${demo.params.n}, w=${demo.params.w}, h=${demo.params.h}`;
  if (state.step >= state.maxStep) {
    elements.demoDetails.innerHTML = renderDemoDetails(demo).join("<br>");
  } else {
    elements.demoDetails.textContent = "Completa gli step per vedere l'esito demo.";
  }
  updateRootIndicator(demo, state.step);
}

function renderTestsTable(demos) {
  if (!tableBody) return;
  tableBody.innerHTML = "";
  Object.keys(demos).forEach((key) => {
    const demo = demos[key];
    const tr = document.createElement("tr");

    const tdName = document.createElement("td");
    tdName.textContent = demo.label || key;

    const tdVerify = document.createElement("td");
    tdVerify.textContent = demo.verify !== undefined ? String(demo.verify) : "-";
    if (demo.verify === true) tdVerify.classList.add("ok");
    if (demo.verify === false) tdVerify.classList.add("bad");

    const tdRoot = document.createElement("td");
    if (demo.root_match !== undefined) {
      tdRoot.textContent = String(demo.root_match);
      tdRoot.classList.add(demo.root_match ? "ok" : "bad");
    } else {
      tdRoot.textContent = "-";
    }

    const tdNote = document.createElement("td");
    const parts = [];
    if (demo.note) parts.push(demo.note);
    if (demo.error) parts.push(`error: ${demo.error}`);
    if (demo.idx_monotonic !== undefined) parts.push(`idx_monotonic: ${demo.idx_monotonic}`);
    if (demo.exhausted !== undefined) parts.push(`exhausted: ${demo.exhausted}`);
    if (demo.rollback_same_idx !== undefined) parts.push(`rollback_same_idx: ${demo.rollback_same_idx}`);
    tdNote.textContent = parts.join(" | ") || "-";

    tr.appendChild(tdName);
    tr.appendChild(tdVerify);
    tr.appendChild(tdRoot);
    tr.appendChild(tdNote);
    tableBody.appendChild(tr);
  });
}

async function init() {
  const response = await fetch(DATA_PATH);
  if (!response.ok) {
    elements.nodeDetails.textContent = `Errore nel caricamento di ${DATA_PATH}`;
    return;
  }
  const data = await response.json();
  state.data = data;
  if (!data.demos) {
    elements.demoDetails.textContent = "Demo non disponibili nel JSON.";
    elements.demoSelect.disabled = true;
    return;
  }
  const demoKeys = Object.keys(data.demos);
  if (demoKeys.length === 0) {
    elements.demoDetails.textContent = "Demo non disponibili nel JSON.";
    elements.demoSelect.disabled = true;
    return;
  }
  elements.demoSelect.innerHTML = "";
  demoKeys.forEach((key) => {
    const demo = data.demos[key];
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = demo.label || key;
    elements.demoSelect.appendChild(opt);
  });
  elements.demoSelect.value = demoKeys[0];
  applyDemo();
  renderTestsTable(data.demos);
  elements.demoSelect.addEventListener("change", () => {
    state.step = 0;
    applyDemo();
  });
  elements.legendFormulas.textContent =
    "Legenda valori:\n" +
    "KEY: chiave derivata da PRF(pub_seed, ADRS) con keyAndMask=0\n" +
    "BM0/BM1: bitmask derivate da PRF(pub_seed, ADRS) con keyAndMask=1/2\n" +
    "LEFT/RIGHT: nodi figli al livello corrente\n" +
    "masked_left = LEFT xor BM0\n" +
    "masked_right = RIGHT xor BM1\n" +
    "Node = H(KEY, masked_left || masked_right)\n" +
    "Mp: hash del messaggio (H_msg) usato per WOTS+\n" +
    "\n" +
    "Parametri pubblici:\n" +
    "pub_seed: seed pubblico usato per PRF\n" +
    "root: radice dell'albero di Merkle\n" +
    "n: lunghezza (byte) degli hash\n" +
    "w: parametro Winternitz\n" +
    "h: altezza dell'albero (2^h foglie)\n" +
    "target_idx: indice della foglia firmata\n";
  wireControls();
}

init();
