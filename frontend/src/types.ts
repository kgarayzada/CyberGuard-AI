export type Section={title:string;body:string};
export type Finding={id:string;title:string;severity:string;status:string;cwe:string;confidence:number;category:string;resource:string;description:string;evidence:string;technical_impact:string;business_impact:string;remediation:string[];related:string[];path:string|null;cvss:number;asset:string;first_detected:string;last_detected:string;risk:number;factors:{label:string;value:number}[];priority:string;analysis?:Section[]};
export type Scan={id:string;date:string;status:string;score:number|null;duration:number;progress:number;stage:string;started:number;findings:Finding[]};
export type Asset={id:string;name:string;url:string;environment:string;exposure:string;type:string;status:string;owner:string;criticality:string};
export type AttackPath={id:string;title:string;severity:string;score:number;findings:string[];nodes:string[];explanation:string;fix_order:string[]};
export type State={asset:Asset;findings:Finding[];scans:Scan[];paths:AttackPath[];questions:string[];disclaimer:string;summary:{score:number;previous:number;open:number;resolved:number;severity:Record<string,number>}};
export type Answer={title:string;intro:string;sections:Section[];method?:string};
export type Report=State & {id?:string;generated:string;assessment:Scan;analysis:Answer;priorities:Answer};
