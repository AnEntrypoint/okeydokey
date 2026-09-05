// One rotation loop, shared by every caller that talks to a credentialed
// upstream. Hosts that write their own copy of this loop drift apart: the
// three copies this replaced disagreed on whether the final credential in a
// set gets marked failed, which decides whether the next request re-tries a
// credential already known to be rejected.

const readStatus = (result) => (result && typeof result.status === "number" ? result.status : 0);

// Tries each usable credential for `ref` in order, advancing on the reasons a
// different credential could plausibly fix (auth, rate limit) and stopping on
// anything else -- a 5xx or a real application error is the upstream's answer,
// not this credential's, so burning the rest of the set on it helps nobody.
export async function rotateCredentials(ring, ref, attempt, { statusOf = readStatus, onRotate } = {}) {
  const usable = ring.usable(ref);
  const order = usable.length > 0 ? usable : ring.has(ref) ? [ring.select(ref)] : [];
  if (order.length === 0) {
    return { exhausted: true, result: null, credential: null, index: -1, candidateCount: 0, rotations: 0 };
  }

  let result = null;
  let credential = null;
  let index = -1;
  let rotations = 0;

  for (let i = 0; i < order.length; i++) {
    credential = order[i];
    index = i;
    result = await attempt(credential, i);

    const status = statusOf(result);
    const reason = ring.classify(status);

    if (ring.isBackoffWorthy(reason)) {
      ring.markFailed(ref, credential, reason);
      if (i < order.length - 1) {
        rotations += 1;
        onRotate?.({ ref, reason, index: i, nextIndex: i + 1, candidateCount: order.length });
        continue;
      }
      break;
    }

    if (status >= 200 && status < 300) ring.markOk(ref, credential);
    break;
  }

  return { exhausted: false, result, credential, index, candidateCount: order.length, rotations };
}
