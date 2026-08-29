import { logs } from "../store/memoryStore.js";

// Appends security events to the temporary memory store
export function logEvent(user, endpoint, score, decision) {
  const entry = {
    user,
    endpoint,
    score,
    decision,
    timestamp: new Date()
  };

  logs.push(entry);

  // Output the event to the developer console
  console.log(
    "[SECURITY]",
    user,
    endpoint,
    "Score:", score,
    "Decision:", decision
  );
}