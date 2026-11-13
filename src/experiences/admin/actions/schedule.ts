'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireAdmin, requireModulePermission, requireOrgMember } from '@/lib/auth';
import { toInt } from '@/lib/text';
import { zonedLocalToUtc } from '@/lib/time';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  good,
  guid,
  optionalGuid,
  str,
  zodProblem,
  type AdminFormState,
  type OverrideOffer,
} from './helpers';
import { loadNames, loadScheduleLookups, nameOf, zoneOf } from '@/experiences/schedule/lookups';
import { getLocation, updateStaffingSwitches } from '@/domains/organizations';
import {
  addTemplateItem,
  applyTemplate,
  archivePosition,
  archiveQualification,
  archiveTemplate,
  assignShift,
  canOfferOverride,
  cancelShift,
  createSchedule,
  createShift,
  decideClaim,
  decideSwap,
  decideTimeOff,
  decisionSchema,
  formatShiftRange,
  getShift,
  RULE_TEXT,
  personQualificationSchema,
  positionShiftsMissingQualification,
  positionSaveSchema,
  publishSchedule,
  qualificationSaveSchema,
  refusedText,
  removePersonQualification,
  removeTemplateItem,
  savePosition,
  saveQualification,
  saveTemplate,
  scheduleCreateSchema,
  setPersonQualification,
  shiftAssignSchema,
  shiftCreateSchema,
  shiftUpdateSchema,
  staffingSettingsSchema,
  templateApplySchema,
  templateItemSchema,
  templateSaveSchema,
  updateShift,
  type AssignRule,
} from '@/domains/staffing';

const SCHEDULE = '/app/admin/schedule';
const REQUESTS = '/app/admin/schedule/requests';

function refreshSchedule() {
  revalidatePath(SCHEDULE);
  revalidatePath('/app/schedule', 'layout');
  revalidatePath('/app');
}

/** The location's time zone, asked of the organizations domain (never trusted from the form). */
async function zoneFor(orgId: string, locationId: string): Promise<string | null> {
  const loc = await getLocation(orgId, locationId);
  return loc.ok && loc.data ? loc.data.timezone : null;
}

// ---- schedules and shifts ----

export async function createScheduleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const parsed = scheduleCreateSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    week_start: str(formData, 'week_start'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createSchedule(parsed.data);
  if (result.ok) refreshSchedule();
  return fromResult(formData, result, 'Schedule started. It is a draft: nobody sees it yet.');
}

export async function publishScheduleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  const id = guid(formData, 'schedule_id');
  if (!locationId || !id) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await publishSchedule(id);
  if (result.ok) refreshSchedule();
  return fromResult(formData, result, 'Published. People with shifts will be told.');
}

export async function addShiftAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const zone = await zoneFor(orgId, locationId);
  if (!zone) return bad(formData, BAD_ID);
  const starts = zonedLocalToUtc(str(formData, 'starts_at'), zone);
  const ends = zonedLocalToUtc(str(formData, 'ends_at'), zone);
  if (!starts || !ends) return bad(formData, 'Enter the start and end of the shift.');
  const parsed = shiftCreateSchema.safeParse({
    schedule_id: str(formData, 'schedule_id').trim(),
    position_id: str(formData, 'position_id').trim(),
    starts_at: starts,
    ends_at: ends,
    notes: str(formData, 'notes'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createShift(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refreshSchedule();
  return good('Shift added. It has nobody on it yet: assign someone below.');
}

export async function updateShiftAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  const id = guid(formData, 'shift_id');
  if (!locationId || !id) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const zone = await zoneFor(orgId, locationId);
  if (!zone) return bad(formData, BAD_ID);
  const starts = zonedLocalToUtc(str(formData, 'starts_at'), zone);
  const ends = zonedLocalToUtc(str(formData, 'ends_at'), zone);
  if (!starts || !ends) return bad(formData, 'Enter the start and end of the shift.');
  const parsed = shiftUpdateSchema.safeParse({
    shift_id: id,
    position_id: str(formData, 'position_id').trim() || null,
    starts_at: starts,
    ends_at: ends,
    // Blank clears the notes (the form shows the current note); null would keep them.
    notes: str(formData, 'notes'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateShift(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refreshSchedule();
  return good('Saved.');
}

/**
 * Gives a shift to a person (blank person = open it). When the database refuses for time off or
 * a missing qualification and the caller is a schedule admin (and the person is not the caller),
 * the answer carries an offer: who, which shift, which rule. The second, explicit "Assign anyway"
 * button sends override=yes. Before acting on it the server asks again without the override and
 * goes ahead only if the same rule still refuses. An overlap or a person who cannot work there
 * never offers it.
 */
export async function assignShiftAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, BAD_ID);
  const member = await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const person = optionalGuid(formData, 'person_id');
  if (person === undefined) return bad(formData, BAD_ID);
  const override = str(formData, 'override') === 'yes';
  const parsed = shiftAssignSchema.safeParse({
    shift_id: str(formData, 'shift_id').trim(),
    person_id: person,
    override: false,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);

  const first = await assignShift(parsed.data);
  if (first.ok) {
    refreshSchedule();
    return good(person ? 'Assigned.' : 'The shift is open now.');
  }
  const isAdmin = await requireModuleLevel(orgId, locationId);
  const self = person !== null && person === member.personId;
  if (!person || self || !first.rule || !canOfferOverride(first.rule, isAdmin)) {
    return bad(formData, first.message);
  }
  if (!override) {
    return {
      ok: false,
      message: first.message,
      offer: await describeOffer(orgId, parsed.data.shift_id, person, first.rule, {
        location_id: locationId,
        shift_id: parsed.data.shift_id,
        person_id: person,
        rule: first.rule,
      }),
    };
  }
  // Override pressed: only for the refusal that was shown.
  if (str(formData, 'rule') !== first.rule) return bad(formData, first.message);
  const second = await assignShift({ ...parsed.data, override: true });
  if (!second.ok) return bad(formData, second.message);
  refreshSchedule();
  return good('Assigned, with the rule overridden. This is recorded.');
}

/** Who, which shift and which rule, in words, built from the database (not from the form). */
async function describeOffer(
  orgId: string,
  shiftId: string,
  personId: string,
  rule: AssignRule,
  fields: Record<string, string>,
): Promise<OverrideOffer> {
  const [shift, names, lookups] = await Promise.all([
    getShift(orgId, shiftId),
    loadNames(orgId, [personId]),
    loadScheduleLookups(orgId),
  ]);
  const s = shift.ok ? shift.data : null;
  const when = s
    ? `${formatShiftRange(s.starts_at, s.ends_at, zoneOf(lookups, s.location_id))}, ${
        lookups.positions.get(s.position_id) ?? 'Shift'
      }`
    : 'this shift';
  return {
    message: `${nameOf(names, personId)} cannot take ${when}. ${RULE_TEXT[rule]} You can assign them anyway. This is recorded.`,
    fields,
  };
}

async function requireModuleLevel(orgId: string, locationId: string): Promise<boolean> {
  try {
    await requireModulePermission(orgId, locationId, 'staff_schedule', 'admin');
    return true;
  } catch {
    return false;
  }
}

export async function cancelShiftAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  const id = guid(formData, 'shift_id');
  if (!locationId || !id) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await cancelShift(id);
  if (result.ok) refreshSchedule();
  return fromResult(formData, result, 'Shift cancelled.');
}

export async function applyTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const day = toInt(formData.get('first_day'));
  const parsed = templateApplySchema.safeParse({
    schedule_id: str(formData, 'schedule_id').trim(),
    template_id: str(formData, 'template_id').trim(),
    ...(day === null ? {} : { first_day: day }),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await applyTemplate(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refreshSchedule();
  const made = result.data.filter((r) => r.shift_id !== null);
  const notes = new Map<string, number>();
  for (const r of result.data) {
    if (r.shift_id !== null && r.refused === null && r.assigned_person_id !== null) continue;
    const text = r.refused
      ? refusedText(r.refused)
      : 'Left open. No one was chosen in the template.';
    notes.set(text, (notes.get(text) ?? 0) + 1);
  }
  const why = [...notes].map(([text, n]) => `${n}: ${text}`).join(' ');
  return good(
    `Added ${made.length} ${made.length === 1 ? 'shift' : 'shifts'}.` + (why ? ` ${why}` : ''),
  );
}

// ---- requests ----

type DecideKind = 'swap' | 'claim';

/**
 * Approve or deny a swap, drop or claim. A refusal for time off or a missing qualification
 * becomes an offer (server-built, naming the person, shift and rule) for a schedule admin, unless
 * one of the people involved is the caller. The override button re-checks the same refusal first.
 */
async function decideRequest(kind: DecideKind, formData: FormData): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const member = await requireOrgMember(orgId);
  const approve = str(formData, 'decision') === 'approve';
  const override = str(formData, 'override') === 'yes';
  const idField = kind === 'swap' ? 'swap_id' : 'claim_id';
  const parsed = decisionSchema.safeParse({
    id: str(formData, idField).trim(),
    approve,
    override: false,
  });
  if (!parsed.success) return bad(formData, BAD_ID);
  const decide = kind === 'swap' ? decideSwap : decideClaim;
  const first = await decide(parsed.data);
  if (first.ok) {
    refreshSchedule();
    revalidatePath(REQUESTS);
    return good(approve ? 'Approved.' : 'Not approved.');
  }
  const locationId = guid(formData, 'location_id');
  const shiftId = guid(formData, 'shift_id');
  const personId = guid(formData, 'person_id');
  const parties = str(formData, 'party_ids')
    .split(',')
    .filter((v) => v !== '');
  const isAdmin = locationId ? await requireModuleLevel(orgId, locationId) : false;
  const involvesMe = member.personId !== null && parties.includes(member.personId);
  if (
    !approve ||
    !first.rule ||
    !canOfferOverride(first.rule, isAdmin) ||
    involvesMe ||
    !locationId ||
    !shiftId ||
    !personId
  ) {
    return bad(formData, first.message);
  }
  if (!override) {
    return {
      ok: false,
      message: first.message,
      offer: await describeOffer(orgId, shiftId, personId, first.rule, {
        [idField]: parsed.data.id,
        location_id: locationId,
        shift_id: shiftId,
        person_id: personId,
        party_ids: parties.join(','),
        decision: 'approve',
        rule: first.rule,
      }),
    };
  }
  if (str(formData, 'rule') !== first.rule) return bad(formData, first.message);
  const second = await decide({ ...parsed.data, override: true });
  if (!second.ok) return bad(formData, second.message);
  refreshSchedule();
  revalidatePath(REQUESTS);
  return good('Approved, with the rule overridden. This is recorded.');
}

export async function decideSwapAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  return decideRequest('swap', formData);
}

export async function decideClaimAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  return decideRequest('claim', formData);
}

export async function decideTimeOffAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'time_off_id');
  if (!id) return bad(formData, BAD_ID);
  const approve = str(formData, 'decision') === 'approve';
  const result = await decideTimeOff(id, approve);
  if (result.ok) revalidatePath(REQUESTS);
  return fromResult(formData, result, approve ? 'Approved.' : 'Not approved.');
}

// ---- positions, qualifications ----

export async function savePositionAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = optionalGuid(formData, 'location_id');
  if (locationId === undefined) return bad(formData, 'Pick a location from the list.');
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'admin');
  const qualificationIds = formData
    .getAll('qualification_ids')
    .filter((v): v is string => typeof v === 'string');
  const parsed = positionSaveSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    name: str(formData, 'name'),
    qualification_ids: qualificationIds,
    position_id: guid(formData, 'position_id'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await savePosition(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/positions');
  // A new requirement can leave people on upcoming shifts without it: say so.
  const missing = await positionShiftsMissingQualification(result.data);
  const n = missing.ok ? missing.data : 0;
  return good(
    n > 0
      ? `Saved. ${n} upcoming ${n === 1 ? 'shift has' : 'shifts have'} someone missing this qualification.`
      : 'Saved.',
  );
}

export async function archivePositionAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'position_id');
  if (!id) return bad(formData, BAD_ID);
  const archived = str(formData, 'archived') !== 'no';
  const result = await archivePosition(id, archived);
  if (result.ok) revalidatePath('/app/admin/positions');
  return fromResult(formData, result, archived ? 'Archived.' : 'Restored.');
}

export async function saveQualificationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = qualificationSaveSchema.safeParse({
    organization_id: orgId,
    name: str(formData, 'name'),
    qualification_id: guid(formData, 'qualification_id'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await saveQualification(parsed.data);
  if (result.ok) revalidatePath('/app/admin/qualifications');
  return fromResult(formData, result, 'Saved.');
}

export async function archiveQualificationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'qualification_id');
  if (!id) return bad(formData, BAD_ID);
  const archived = str(formData, 'archived') !== 'no';
  const result = await archiveQualification(id, archived);
  if (result.ok) revalidatePath('/app/admin/qualifications');
  return fromResult(formData, result, archived ? 'Archived.' : 'Restored.');
}

export async function setHolderAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = personQualificationSchema.safeParse({
    organization_id: orgId,
    person_id: str(formData, 'person_id').trim(),
    qualification_id: str(formData, 'qualification_id').trim(),
    valid_from: str(formData, 'valid_from') || null,
    expires_on: str(formData, 'expires_on') || null,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await setPersonQualification(parsed.data);
  if (result.ok) revalidatePath('/app/admin/qualifications');
  return fromResult(formData, result, 'Saved.');
}

export async function removeHolderAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'holder_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await removePersonQualification(id);
  if (result.ok) revalidatePath('/app/admin/qualifications');
  return fromResult(formData, result, 'Removed.');
}

// ---- templates ----

export async function saveTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, 'Pick a location from the list.');
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const span = toInt(formData.get('span_days'));
  const templateId = guid(formData, 'template_id');
  const parsed = templateSaveSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    name: str(formData, 'name'),
    template_id: templateId,
    ...(templateId || span === null ? {} : { span_days: span }),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await saveTemplate(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/shift-templates');
  if (!templateId) redirect(`/app/admin/shift-templates/${result.data}`);
  return good('Saved.');
}

export async function archiveTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  const id = guid(formData, 'template_id');
  if (!locationId || !id) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const archived = str(formData, 'archived') !== 'no';
  const result = await archiveTemplate(id, archived);
  if (result.ok) revalidatePath('/app/admin/shift-templates');
  return fromResult(formData, result, archived ? 'Archived.' : 'Restored.');
}

export async function addTemplateItemAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'staff_schedule', 'edit');
  const day = toInt(formData.get('day_offset'));
  const minutes = toInt(formData.get('duration_minutes'));
  const parsed = templateItemSchema.safeParse({
    template_id: str(formData, 'template_id').trim(),
    position_id: str(formData, 'position_id').trim(),
    day_offset: day ?? -1,
    start_time: str(formData, 'start_time'),
    duration_minutes: minutes ?? 0,
    assigned_person_id: guid(formData, 'assigned_person_id'),
    notes: str(formData, 'notes'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await addTemplateItem(parsed.data);
  if (result.ok) revalidatePath(`/app/admin/shift-templates/${parsed.data.template_id}`);
  return fromResult(formData, result, 'Added.');
}

export async function removeTemplateItemAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'item_id');
  const templateId = guid(formData, 'template_id');
  if (!id || !templateId) return bad(formData, BAD_ID);
  const result = await removeTemplateItem(id);
  if (result.ok) revalidatePath(`/app/admin/shift-templates/${templateId}`);
  return fromResult(formData, result, 'Removed.');
}

// ---- settings ----

export async function updateStaffingSwitchesAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const parsed = staffingSettingsSchema.safeParse({
    auto_approve_swaps: formData.get('auto_approve_swaps') === 'yes',
    first_come_open_shifts: formData.get('first_come_open_shifts') === 'yes',
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateStaffingSwitches(orgId, parsed.data);
  if (result.ok) revalidatePath('/app/admin/settings');
  return fromResult(formData, result, 'Saved.');
}
