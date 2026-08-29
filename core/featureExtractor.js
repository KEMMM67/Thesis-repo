// Extracts raw request data into measurable behavioral metrics
export function extractFeatures(activity) {
  const requestRate = activity.rate;
  const endpointDiversity = activity.endpoints;
  const loginAttempts = activity.loginAttempts;
  const sessionDuration = activity.sessionDuration / 1000;

  // Apply weight multipliers based on user privileges
  let roleFactor = 1;
  if (activity.role === "admin") roleFactor = 1.2;
  if (activity.role === "faculty") roleFactor = 1.1;
  if (activity.role === "student") roleFactor = 1.0;

  return {
    requestRate,
    endpointDiversity,
    loginAttempts,
    sessionDuration,
    roleFactor
  };
}