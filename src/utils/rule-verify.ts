import { EnumValueType, GenerateRuleModesType } from 'hrbac';

export const ruleVerify = <A extends EnumValueType>(r: GenerateRuleModesType<A>) => r;

// == test ==
// const r = {
//   description: ruleVerify<ActionType>(['create', 'some']),
//   // TS2345: Argument of type 'CaRUDA' is not assignable to parameter of type '..'|'..'|..
//   title: ruleVerify<ActionType>(['CaRUDA']),
// };
//
// console.log(r);
