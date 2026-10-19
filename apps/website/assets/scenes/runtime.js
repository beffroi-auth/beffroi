// The runtime a scene plays on. A scene draws its still frame in the markup; this file only ever adds motion to it,
// and takes care of what every scene must do the same way:
// - nothing at all under prefers-reduced-motion, and back to the still frame if it is turned on while playing;
// - the scene starts once the logo intro is over (0.3 s);
// - every animation and every timer lives on the document timeline, so one pause stops the whole scene: off screen
//   (IntersectionObserver) and in a hidden tab;
// - the rounds follow one another for as long as the page is open.

const SVG = 'http://www.w3.org/2000/svg';
const INTRO = 300;

/**
 * @typedef {object} Stage
 * @property {SVGSVGElement} svg the overlay of the scene, [data-scene="<name>"]
 * @property {SVGGElement} cast [data-cast] inside the overlay, given back its still frame if motion stops
 * @property {<T extends Animation>(animation: T) => T} track registers an animation so pauses and cancellations reach it
 * @property {(target: Element, keyframes: Keyframe[], options: KeyframeAnimationOptions) => Animation} animate target.animate(), registered
 * @property {(ms: number) => Promise<boolean>} at resolves true after `ms` of scene time (paused with the scene), false if the scene was cancelled
 * @property {(name: string, attributes: Record<string, string|number>, parent: Element) => SVGElement} make creates an SVG element and appends it
 */

/**
 * @param {string} name
 * @param {{keepsCast?: boolean, setup?: (stage: Stage) => void, round: (stage: Stage, index: number) => number}} definition
 *   keepsCast: the scene removes what it drew once it is done with it, so the cast is emptied before the first round
 *   only and a round may start while the previous one is still on stage; round() builds round `index` into the cast
 *   and returns when the next round starts, in ms from now.
 */
export function runScene(name, definition) {
  const svg = document.querySelector(`svg[data-scene="${name}"]`);
  const cast = svg?.querySelector('[data-cast]');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (!svg || !cast || reduce.matches || typeof Element.prototype.animate !== 'function') return;
  if (svg.dataset.started !== undefined) return;
  svg.dataset.started = '';

  const still = cast.innerHTML;
  const tracked = new Set();
  let running = true;
  let cancelled = false;

  const track = (animation) => {
    tracked.add(animation);
    const drop = () => tracked.delete(animation);
    animation.finished.then(drop, drop);
    if (!running) animation.pause();
    return animation;
  };

  const animate = (target, keyframes, options) => track(target.animate(keyframes, options));

  const at = (ms) =>
    track(svg.animate([], { duration: 0, delay: Math.max(0, ms) })).finished.then(
      () => !cancelled,
      () => false,
    );

  const make = (tag, attributes, parent) => {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    parent.append(node);
    return node;
  };

  /** @type {Stage} */
  const stage = { svg, cast, track, animate, at, make };

  // Everything that moves: what the runtime registered, and any CSS animation the scene runs in its overlay.
  const everything = () => new Set([...tracked, ...svg.getAnimations({ subtree: true })]);

  let onScreen = true;
  const sync = () => {
    const should = onScreen && !document.hidden && !cancelled;
    if (should === running) return;
    running = should;
    for (const animation of everything()) {
      if (should) animation.play();
      else animation.pause();
    }
  };
  document.addEventListener('visibilitychange', sync);
  new IntersectionObserver(([entry]) => {
    onScreen = entry?.isIntersecting ?? true;
    sync();
  }).observe(svg);

  reduce.addEventListener('change', () => {
    if (!reduce.matches) return;
    cancelled = true;
    for (const animation of everything()) animation.cancel();
    cast.innerHTML = still;
  });

  const play = async () => {
    if (!(await at(INTRO))) return;
    definition.setup?.(stage);
    for (let index = 0; ; index += 1) {
      if (index === 0 || !definition.keepsCast) cast.replaceChildren();
      const length = definition.round(stage, index);
      if (!(await at(length))) return;
    }
  };

  void play();
}
