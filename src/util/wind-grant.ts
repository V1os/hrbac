type Resource = 'client' | 'admin' | 'role' | 'permission';
type RuleMode = 'C' | 'R' | 'U' | 'D' | 'B';
type RuleModes =
  | `${RuleMode}`
  | `${RuleMode}${RuleMode}`
  | `${RuleMode}${RuleMode}${RuleMode}`
  | `${RuleMode}${RuleMode}${RuleMode}${RuleMode}`
  | `${RuleMode}${RuleMode}${RuleMode}${RuleMode}${RuleMode}`;
type Grants = Record<Resource, RuleModes>;

const ruleMap: Record<RuleMode, string> = { C: 'create', R: 'read', U: 'update', D: 'delete', B: 'block' };

export const windGrant = (options: Partial<Grants>, delimiter = '_') => {
  const grants: string[] = [];

  for (const [resource, rules = 'R'] of Object.entries(options)) {
    for (const rule of rules as unknown as RuleMode[]) {
      grants.push(`${ruleMap[rule]}${delimiter}${resource}`);
    }
  }

  return grants;
};
