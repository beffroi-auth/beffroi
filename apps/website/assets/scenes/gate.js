// The scene of the gate (templates/_gate.html.twig): users and services queue on the ground to the right of the tower,
// walk behind its wall and come out in the gate, where the provider checks each one.
// - Let in: the outline of the gate lights green, a green mark shows over the visitor, who walks on through the gate,
//   in front of the left leg of the tower, and out of the frame to the left.
// - Turned away: the outline lights red, a red mark shows, the visitor turns round and goes back behind the wall.
// Until its verdict, a figure is clipped by the silhouette of the tower: it shows on the ground and in the opening of
// the gate only. Let in, it loses that clip as it leaves the gate, where the clip hides nothing, so nothing jumps.
import { runScene } from './runtime.js';

// The still frame shows a user let in at the gate and a service waiting: the first round resumes from there.
const roster = [
  { kind: 'person', ok: true },
  { kind: 'service', ok: true },
  { kind: 'person', ok: false },
  { kind: 'person', ok: true },
  { kind: 'service', ok: false },
  { kind: 'service', ok: true },
];

const GREEN = '#c6f432'; // the signal green of the brand
const RED = '#ff3d2e';
const OUTLINED = { stroke: '#f2f4f6', 'stroke-width': 0.5, 'stroke-linejoin': 'miter', 'paint-order': 'stroke' };
const GATE_EDGE = 'M26.3 60V50.124L32 44.424L37.7 50.124V60'; // gate_edge of the template

// Positions on the ground line, in units of the symbol. The opening of the gate spans 26 to 38, the plinth of the
// tower ends at 52: the queue waits at 56, on the ground beside it. Let in, a visitor walks on to the left, in front
// of the left leg, and out of the frame; turned away, back behind the right wall, where the tower hides it.
const GROUND = 60;
const SPAWN = 72;
const WAIT = 56;
const GATE = 32;
const EXIT = -30;
const BACK = 46;
const SPEED = 0.01; // 10 u per second

// Times, in ms.
const CHECK = 450; // at the gate, before the verdict
const HOLD = 650; // the verdict shown, before the visitor moves
const LIGHT_IN = 120;
const LIGHT_OUT = 300;
const STRIDE = 320; // one stride: up, down
const QUEUE_GAP = 800; // the next in line reaches the queue 8 u behind the one who left it
const DWELL = 600; // a pause in the queue
const GATE_GAP = 900; // the opening stays empty this long between two visitors
const CLEAR_IN = 800; // from leaving the gate to clearing the opening, 8 u to the left
const CLEAR_BACK = 1000; // the same, 10 u to the right, for a mirrored figure
const SPACING = 1800; // between two arrivals, at least

const walkIn = (SPAWN - WAIT) / SPEED;
const step = (WAIT - GATE) / SPEED;
const walkOut = (GATE - EXIT) / SPEED;
const walkBack = (BACK - GATE) / SPEED;

const visitorAt = (index) => roster[index % roster.length];

// When each visitor reaches the queue, steps up to the gate, hears the verdict and goes. In a resumed round the first
// visitor is already at the gate, verdict shown, and the second already waits in the queue. `start` is when the next
// round may send its first visitor in: the same spacing as between two visitors of one round, so the loop has no seam
// while the last visitor of a round is still walking away.
function plan(list, resume) {
  let next = 0;
  let gateFree = Number.NEGATIVE_INFINITY;
  let waitFree = Number.NEGATIVE_INFINITY;

  const visits = list.map((visitor, index) => {
    let spawn;
    let atWait;
    let depart;
    let atGate;
    let verdict;

    if (resume && index === 0) {
      spawn = atWait = depart = atGate = verdict = 0;
    } else if (resume && index === 1) {
      spawn = atWait = 0;
      depart = Math.max(DWELL, gateFree + GATE_GAP - step);
      atGate = depart + step;
      verdict = atGate + CHECK;
    } else {
      spawn = Math.max(next, waitFree + QUEUE_GAP - walkIn);
      atWait = spawn + walkIn;
      depart = Math.max(atWait + DWELL, gateFree + GATE_GAP - step);
      atGate = depart + step;
      verdict = atGate + CHECK;
    }

    const leave = verdict + HOLD;
    const end = leave + (visitor.ok ? walkOut : walkBack);
    waitFree = depart;
    gateFree = leave + (visitor.ok ? CLEAR_IN : CLEAR_BACK);
    next = spawn + SPACING;

    return { ...visitor, resumed: resume && index < 2, spawn, atWait, depart, atGate, verdict, leave, end };
  });

  const start = Math.max(next, waitFree + QUEUE_GAP - walkIn, gateFree + GATE_GAP - step - DWELL - walkIn);
  return { visits, start };
}

function perform(stage, visit) {
  const atGateAlready = visit.resumed && visit.atGate === 0;
  const start = atGateAlready ? GATE : visit.resumed ? WAIT : SPAWN;
  const total = visit.end;
  const offset = (time) => Math.min(1, Math.max(0, time / total));
  const place = (x, time) => ({ transform: `translate(${x}px, ${GROUND}px)`, offset: offset(time) });

  // The outline of the gate lights under the visitor, green or red, from the verdict until the visitor moves on.
  const edge = stage.make(
    'path',
    {
      d: GATE_EDGE,
      fill: 'none',
      stroke: visit.ok ? GREEN : RED,
      'stroke-width': 0.6,
      'stroke-linejoin': 'miter',
      opacity: atGateAlready ? 1 : 0,
    },
    stage.cast,
  );
  stage.cast.prepend(edge);
  const lightEnd = visit.leave + LIGHT_OUT;
  stage.animate(
    edge,
    atGateAlready
      ? [{ opacity: 1 }, { opacity: 1, offset: visit.leave / lightEnd }, { opacity: 0 }]
      : [
          { opacity: 0 },
          { opacity: 1, offset: LIGHT_IN / (lightEnd - visit.verdict) },
          { opacity: 1, offset: HOLD / (lightEnd - visit.verdict) },
          { opacity: 0 },
        ],
    atGateAlready
      ? { duration: lightEnd, fill: 'forwards' }
      : { duration: lightEnd - visit.verdict, delay: visit.verdict, fill: 'forwards' },
  );

  // The clip sits on a group that never moves: a userSpaceOnUse clip is read in the coordinates of the element that
  // references it, transform included, so on the moving figure it would travel with it instead of staying on the
  // tower. Let in, the clip goes as the visitor leaves the gate, and the visitor walks on in front of the left leg.
  const lane = stage.make('g', { 'clip-path': 'url(#gate-clear)' }, stage.cast);
  const body = stage.make('g', { transform: `translate(${start} ${GROUND})`, ...OUTLINED }, lane);
  if (visit.ok) {
    void stage.at(visit.leave).then((reached) => {
      if (reached) lane.removeAttribute('clip-path');
    });
  }
  const gait = stage.make('g', {}, body);
  const front = stage.make('g', {}, gait);
  stage.make('use', { href: `#gate-${visit.kind}` }, front);
  const mark = stage.make(
    'use',
    { href: visit.ok ? '#gate-mark-ok' : '#gate-mark-deny', opacity: atGateAlready ? 1 : 0 },
    body,
  );

  // The path along the ground: in from the right, the queue, behind the wall, the gate, then on to the left or back
  // to the right.
  const path = [place(start, 0)];
  if (!visit.resumed) path.push(place(SPAWN, visit.spawn), place(WAIT, visit.atWait));
  if (!atGateAlready) path.push(place(WAIT, visit.depart), place(GATE, visit.atGate));
  path.push(place(GATE, visit.leave), place(visit.ok ? EXIT : BACK, total));
  stage.animate(body, path, { duration: total, fill: 'both' });

  const stride = (from, to) => {
    if (to - from < STRIDE / 2) return;
    stage.animate(gait, [{ transform: 'translateY(0)' }, { transform: 'translateY(-0.35px)' }], {
      duration: STRIDE,
      delay: from,
      iterations: Math.max(1, Math.round((to - from) / STRIDE)),
      easing: 'steps(2, jump-none)',
    });
  };
  if (!visit.resumed) stride(visit.spawn, visit.atWait);
  if (!atGateAlready) stride(visit.depart, visit.atGate);
  stride(visit.leave, total);

  // Turned away: the figure turns round. Two drawings, the second mirrored by its own transform attribute, so the
  // mirror pivots on the feet whatever the browser makes of a CSS transform origin on SVG.
  if (!visit.ok) {
    const back = stage.make('g', { opacity: 0 }, gait);
    const mirrored = stage.make('g', { transform: 'scale(-1 1)' }, back);
    stage.make('use', { href: `#gate-${visit.kind}` }, mirrored);
    const turn = { duration: 1, delay: Math.max(0, visit.leave - 1), fill: 'forwards' };
    stage.animate(front, [{ opacity: 1 }, { opacity: 0 }], turn);
    stage.animate(back, [{ opacity: 0 }, { opacity: 1 }], turn);
  }

  // The mark shows from the verdict and stays with the visitor: out of the frame to the left, or behind the wall.
  stage.animate(
    mark,
    atGateAlready
      ? [
          { opacity: 1 },
          { opacity: 1, offset: offset(total - LIGHT_OUT) },
          { opacity: 0, offset: offset(total) },
          { opacity: 0 },
        ]
      : [
          { opacity: 0, offset: 0 },
          { opacity: 0, offset: offset(visit.verdict) },
          { opacity: 1, offset: offset(visit.verdict + LIGHT_IN) },
          { opacity: 1, offset: offset(total - LIGHT_OUT) },
          { opacity: 0, offset: offset(total) },
          { opacity: 0, offset: 1 },
        ],
    { duration: total, fill: 'both' },
  );

  // Off stage once out of the frame or behind the wall: the next round plays on while this one walks away.
  void stage.at(lightEnd).then((reached) => {
    if (reached) edge.remove();
  });
  void stage.at(total).then((reached) => {
    if (reached) lane.remove();
  });
}

runScene('gate', {
  keepsCast: true,
  round(stage, index) {
    // Each round starts two visitors further down the roster, so the verdicts do not repeat in the same order.
    const list = roster.map((_, i) => visitorAt(i + index * 2));
    const { visits, start } = plan(list, index === 0);
    for (const visit of visits) perform(stage, visit);
    return start;
  },
});
