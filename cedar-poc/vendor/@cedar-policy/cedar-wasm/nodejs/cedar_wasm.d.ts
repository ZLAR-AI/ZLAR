/* tslint:disable */
/* eslint-disable */
export interface ActionEntityUID<N> {
    id: SmolStr;
    type?: N;
}

export interface ActionType<N> {
    attributes?: Record<SmolStr, CedarValueJson>;
    appliesTo?: ApplySpec<N>;
    memberOf?: ActionEntityUID<N>[];
    annotations?: Annotations;
}

export interface ApplySpec<N> {
    resourceTypes: N[];
    principalTypes: N[];
    context?: AttributesOrContext<N>;
}

export interface AuthorizationCall {
    principal: EntityUid;
    action: EntityUid;
    resource: EntityUid;
    context: Context;
    schema?: Schema;
    validateRequest?: boolean;
    policies: PolicySet;
    entities: Entities;
}

export interface AuthorizationError {
    policyId: string;
    error: DetailedError;
}

export interface ContextParsingCall {
    context: Context;
    schema?: Schema | null;
    action?: EntityUid | null;
}

export interface DetailedError {
    message: string;
    help: string | null;
    code: string | null;
    url: string | null;
    severity: Severity | null;
    sourceLocations?: SourceLabel[];
    related?: DetailedError[];
}

export interface Diagnostics {
    reason: PolicyId[];
    errors: AuthorizationError[];
}

export interface EntitiesParsingCall {
    entities: Entities;
    schema?: Schema | null;
}

export interface EntityJson {
    uid: EntityUidJson;
    attrs: Record<string, CedarValueJson>;
    parents: EntityUidJson[];
    tags?: Record<string, CedarValueJson>;
}

export interface FormattingCall {
    policyText: string;
    lineWidth?: number;
    indentWidth?: number;
}

export interface NamespaceDefinition<N> {
    commonTypes?: Record<CommonTypeId, CommonType<N>>;
    entityTypes: Record<UnreservedId, EntityType<N>>;
    actions: Record<SmolStr, ActionType<N>>;
    annotations?: Annotations;
}

export interface PartialAuthorizationCall {
    principal: EntityUid | null;
    action: EntityUid | null;
    resource: EntityUid | null;
    context: Context;
    schema?: Schema;
    validateRequest?: boolean;
    policies: PolicySet;
    entities: Entities;
}

export interface PolicyJson {
    effect: Effect;
    principal: PrincipalConstraint;
    action: ActionConstraint;
    resource: ResourceConstraint;
    conditions: Clause[];
    annotations?: Annotations;
}

export interface PolicySet {
    staticPolicies?: StaticPolicySet;
    templates?: Record<PolicyId, Template>;
    templateLinks?: TemplateLink[];
}

export interface PrincipalOrResourceIsConstraint {
    entity_type: string;
    in?: PrincipalOrResourceInConstraint;
}

export interface RecordType<N> {
    attributes: Record<SmolStr, TypeOfAttribute<N>>;
    additionalAttributes?: boolean;
}

export interface ResidualResponse {
    decision: Decision | null;
    satisfied: PolicyId[];
    errored: PolicyId[];
    mayBeDetermining: PolicyId[];
    mustBeDetermining: PolicyId[];
    residuals: Record<string, PolicyJson>;
    nontrivialResiduals: PolicyId[];
}

export interface Response {
    decision: Decision;
    diagnostics: Diagnostics;
}

export interface SourceLabel extends SourceLocation {
    label: string | null;
}

export interface SourceLocation {
    start: number;
    end: number;
}

export interface StandardEntityType<N> {
    memberOfTypes?: N[];
    shape?: AttributesOrContext<N>;
    tags?: Type<N>;
}

export interface StatefulAuthorizationCall {
    principal: EntityUid;
    action: EntityUid;
    resource: EntityUid;
    context: Context;
    preparsedSchemaName?: string;
    validateRequest?: boolean;
    preparsedPolicySetId: string;
    entities: Entities;
}

export interface TemplateLink {
    templateId: PolicyId;
    newId: PolicyId;
    values: Record<SlotId, EntityUid>;
}

export interface TypeAndId {
    type: string;
    id: string;
}

export interface ValidationCall {
    validationSettings?: ValidationSettings;
    schema: Schema;
    policies: PolicySet;
}

export interface ValidationError {
    policyId: string;
    error: DetailedError;
}

export interface ValidationSettings {
    mode: ValidationMode;
}

export type ActionConstraint = { op: "All" } | ({ op: "==" } & EqConstraint) | ({ op: "in" } & ActionInConstraint);

export type ActionInConstraint = { entity: EntityUidJson } | { entities: EntityUidJson[] };

export type Annotation = SmolStr;

export type Annotations = Record<string, Annotation>;

export type AnyId = SmolStr;

export type AttributesOrContext<N> = Type<N>;

export type AuthorizationAnswer = { type: "failure"; errors: DetailedError[]; warnings: DetailedError[] } | { type: "success"; response: Response; warnings: DetailedError[] };

export type CedarValueJson = { __entity: TypeAndId } | { __extn: FnAndArgs } | boolean | number | string | CedarValueJson[] | { [key: string]: CedarValueJson } | null;

export type CheckParseAnswer = { type: "success" } | { type: "failure"; errors: DetailedError[] };

export type Clause = { kind: "when"; body: Expr } | { kind: "unless"; body: Expr };

export type CommonTypeId = string;

export type Context = Record<string, CedarValueJson>;

export type Decision = "allow" | "deny";

export type Effect = "permit" | "forbid";

export type Entities = Array<EntityJson>;

export type EntityTypeKind<N> = StandardEntityType<N> | { enum: NonEmpty<SmolStr> };

export type EntityUid = EntityUidJson;

export type EntityUidJson = { __entity: TypeAndId } | TypeAndId;

export type EqConstraint = { entity: EntityUidJson } | { slot: string };

export type Expr = ExprNoExt | ExtFuncCall;

export type ExprNoExt = { Value: CedarValueJson } | { Var: Var } | { Slot: string } | { "!": { arg: Expr } } | { neg: { arg: Expr } } | { "==": { left: Expr; right: Expr } } | { "!=": { left: Expr; right: Expr } } | { in: { left: Expr; right: Expr } } | { "<": { left: Expr; right: Expr } } | { "<=": { left: Expr; right: Expr } } | { ">": { left: Expr; right: Expr } } | { ">=": { left: Expr; right: Expr } } | { "&&": { left: Expr; right: Expr } } | { "||": { left: Expr; right: Expr } } | { "+": { left: Expr; right: Expr } } | { "-": { left: Expr; right: Expr } } | { "*": { left: Expr; right: Expr } } | { contains: { left: Expr; right: Expr } } | { containsAll: { left: Expr; right: Expr } } | { containsAny: { left: Expr; right: Expr } } | { isEmpty: { arg: Expr } } | { getTag: { left: Expr; right: Expr } } | { hasTag: { left: Expr; right: Expr } } | { ".": { left: Expr; attr: SmolStr } } | { has: { left: Expr; attr: SmolStr } } | { like: { left: Expr; pattern: PatternElem[] } } | { is: { left: Expr; entity_type: SmolStr; in?: Expr } } | { "if-then-else": { if: Expr; then: Expr; else: Expr } } | { Set: Expr[] } | { Record: Record<string, Expr> };

export type ExtFuncCall = {} & Record<string, Array<Expr>>;

export type FnAndArgs = { fn: string; arg: CedarValueJson } | { fn: string; args: CedarValueJson[] };

export type FormattingAnswer = { type: "failure"; errors: DetailedError[] } | { type: "success"; formatted_policy: string };

export type GetValidRequestEnvsResult = { type: "success"; principals: string[]; actions: string[]; resources: string[] } | { type: "failure"; error: string };

export type PartialAuthorizationAnswer = { type: "failure"; errors: DetailedError[]; warnings: DetailedError[] } | { type: "residuals"; response: ResidualResponse; warnings: DetailedError[] };

export type PatternElem = "Wildcard" | { Literal: SmolStr };

export type Policy = string | PolicyJson;

export type PolicyId = string;

export type PolicySetTextToPartsAnswer = { type: "success"; policies: string[]; policy_templates: string[] } | { type: "failure"; errors: DetailedError[] };

export type PolicyToJsonAnswer = { type: "success"; json: PolicyJson } | { type: "failure"; errors: DetailedError[] };

export type PolicyToTextAnswer = { type: "success"; text: string } | { type: "failure"; errors: DetailedError[] };

export type PrincipalConstraint = { op: "All" } | ({ op: "==" } & EqConstraint) | ({ op: "in" } & PrincipalOrResourceInConstraint) | ({ op: "is" } & PrincipalOrResourceIsConstraint);

export type PrincipalOrResourceInConstraint = { entity: EntityUidJson } | { slot: string };

export type ResourceConstraint = { op: "All" } | ({ op: "==" } & EqConstraint) | ({ op: "in" } & PrincipalOrResourceInConstraint) | ({ op: "is" } & PrincipalOrResourceIsConstraint);

export type Schema = string | SchemaJson<string>;

export type SchemaJson<N> = Record<string, NamespaceDefinition<N>>;

export type SchemaToJsonAnswer = { type: "success"; json: SchemaJson<string>; warnings: DetailedError[] } | { type: "failure"; errors: DetailedError[] };

export type SchemaToJsonWithResolvedTypesAnswer = { type: "success"; json: SchemaJson<string>; warnings: DetailedError[] } | { type: "failure"; errors: DetailedError[] };

export type SchemaToTextAnswer = { type: "success"; text: string; warnings: DetailedError[] } | { type: "failure"; errors: DetailedError[] };

export type Severity = "advice" | "warning" | "error";

export type SlotId = string;

export type StaticPolicySet = string | Policy[] | Record<PolicyId, Policy>;

export type Template = string | PolicyJson;

export type Type<N> = ({} & TypeVariant<N>) | { type: N };

export type TypeVariant<N> = { type: "String" } | { type: "Long" } | { type: "Boolean" } | { type: "Set"; element: Type<N> } | ({ type: "Record" } & RecordType<N>) | { type: "Entity"; name: N } | { type: "EntityOrCommon"; name: N } | { type: "Extension"; name: UnreservedId };

export type UnreservedId = string;

export type ValidationAnswer = { type: "failure"; errors: DetailedError[]; warnings: DetailedError[] } | { type: "success"; validationErrors: ValidationError[]; validationWarnings: ValidationError[]; otherWarnings: DetailedError[] };

export type ValidationMode = "strict";

export type Var = "principal" | "action" | "resource" | "context";


/**
 * Check whether a context successfully parses.
 */
export function checkParseContext(call: ContextParsingCall): CheckParseAnswer;

/**
 * Check whether a set of entities successfully parses.
 */
export function checkParseEntities(call: EntitiesParsingCall): CheckParseAnswer;

/**
 * Check whether a policy set successfully parses.
 */
export function checkParsePolicySet(policies: PolicySet): CheckParseAnswer;

/**
 * Check whether a schema successfully parses.
 */
export function checkParseSchema(schema: Schema): CheckParseAnswer;

/**
 * Apply the Cedar policy formatter to a policy set in the Cedar policy format
 */
export function formatPolicies(call: FormattingCall): FormattingAnswer;

/**
 * Get language version of Cedar
 */
export function getCedarLangVersion(): string;

export function getCedarSDKVersion(): string;

export function getCedarVersion(): string;

/**
 * Get valid request environment
 */
export function getValidRequestEnvsPolicy(t: Policy, s: Schema): GetValidRequestEnvsResult;

/**
 * Get valid request environment
 */
export function getValidRequestEnvsTemplate(t: Template, s: Schema): GetValidRequestEnvsResult;

/**
 * Basic interface, using [`AuthorizationCall`] and [`AuthorizationAnswer`] types
 */
export function isAuthorized(call: AuthorizationCall): AuthorizationAnswer;

/**
 * Basic interface for partial evaluation, using [`AuthorizationCall`] and
 * [`PartialAuthorizationAnswer`] types
 */
export function isAuthorizedPartial(call: PartialAuthorizationCall): PartialAuthorizationAnswer;

/**
 * Takes a `PolicySet` represented as string and return the policies
 * and templates split into vecs and sorted by id.
 */
export function policySetTextToParts(policyset_str: string): PolicySetTextToPartsAnswer;

/**
 * Return the JSON representation of a policy.
 */
export function policyToJson(policy: Policy): PolicyToJsonAnswer;

/**
 * Return the Cedar (textual) representation of a policy.
 */
export function policyToText(policy: Policy): PolicyToTextAnswer;

/**
 * Preparse and cache a policy set in thread-local storage
 *
 * # Errors
 *
 * Will return `Err` if the input cannot be parsed. Side-effect free on error.
 */
export function preparsePolicySet(pset_id: string, policies: PolicySet): CheckParseAnswer;

/**
 * Preparse and cache a schema in thread-local storage
 *
 * # Errors
 *
 * Will return `Err` if the input cannot be parsed. Side-effect free on error.
 */
export function preparseSchema(schema_name: string, schema: Schema): CheckParseAnswer;

/**
 * Return the JSON representation of a schema.
 */
export function schemaToJson(schema: Schema): SchemaToJsonAnswer;

/**
 * Convert a Cedar schema string to JSON format with resolved types.
 *
 * This function resolves ambiguous "`EntityOrCommon`" types to their specific
 * Entity or `CommonType` classifications using the schema's type definitions.
 * This is primarily meant to be used when working with schemas programmatically,
 * for example when creating a schema building UI.
 */
export function schemaToJsonWithResolvedTypes(schema_str: string): SchemaToJsonWithResolvedTypesAnswer;

/**
 * Return the Cedar (textual) representation of a schema.
 */
export function schemaToText(schema: Schema): SchemaToTextAnswer;

/**
 * Stateful authorization using preparsed schemas and policy sets.
 *
 * This function works like [`is_authorized`] but retrieves schemas and policy sets
 * from thread-local cache instead of parsing them on each call.
 */
export function statefulIsAuthorized(call: StatefulAuthorizationCall): AuthorizationAnswer;

/**
 * Return the JSON representation of a template.
 */
export function templateToJson(template: Template): PolicyToJsonAnswer;

/**
 * Return the Cedar (textual) representation of a template.
 */
export function templateToText(template: Template): PolicyToTextAnswer;

/**
 * Parse a policy set and optionally validate it against a provided schema
 *
 * This is the basic validator interface, using [`ValidationCall`] and
 * [`ValidationAnswer`] types
 */
export function validate(call: ValidationCall): ValidationAnswer;
type SmolStr = string;
export type TypeOfAttribute<N> = Type<N> & { required?: boolean };
export type CommonType<N> = Type<N> & { annotations?: Annotations };
export type EntityType<N> = EntityTypeKind<N> & { annotations?: Annotations; };
export type NonEmpty<Type> = Array<Type>;
