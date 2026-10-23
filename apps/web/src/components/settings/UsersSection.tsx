import {
  ROLE_LABELS,
  ROLES,
  userCreateRequestSchema,
  type Role,
  type User,
  type UserUpdateRequest,
} from '@exdomainvault/shared';
import { UserPlus, Users } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';
import { ApiClientError, api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { useSession } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Pagination } from '../findings/Pagination.tsx';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { ConfirmPanel } from './ConfirmPanel.tsx';

const PAGE_SIZE = 25;
const inputClass = 'w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm';
const selectClass = 'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm shadow-sm';

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));
const isRole = (v: string | null): v is Role =>
  v !== null && (ROLES as readonly string[]).includes(v);

/**
 * Rewrites the server's 409 guard responses (`details[0].path`) into plain words. The server is the
 * authority: these messages only explain what it refused.
 */
function plainUserError(err: Error, isSelf: boolean): Error {
  if (!(err instanceof ApiClientError) || err.status !== 409) return err;
  const path = err.details?.[0]?.path;
  let message: string;
  if (path === 'email') {
    message = 'A user with this email address already exists.';
  } else if (path === 'role') {
    message = isSelf
      ? 'You cannot change your own role. Ask another administrator to do it.'
      : 'This is the last active administrator, so their role cannot be changed. Make another user an administrator first.';
  } else if (path === 'isActive') {
    message = isSelf
      ? 'You cannot deactivate your own account. Ask another administrator to do it.'
      : 'This is the last active administrator, so they cannot be deactivated. Make another user an administrator first.';
  } else {
    return err;
  }
  return new ApiClientError(message, err.status, err.code, err.requestId);
}

/** User administration (`users:manage`). The API enforces every rule shown here. */
export function UsersSection() {
  const session = useSession();
  const currentUserId = session.status === 'success' ? session.data.user.id : null;
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get('page')) || 1);
  const q = params.get('q') ?? '';
  const roleParam = params.get('role');
  const role = isRole(roleParam) ? roleParam : '';
  const activeParam = params.get('active');
  const active = activeParam === 'true' || activeParam === 'false' ? activeParam : '';
  const [search, setSearch] = useState(q);
  const [reload, setReload] = useState(0);
  const [message, setMessage] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  const state = useAsync(
    (signal) =>
      api.users.list(
        { page, pageSize: PAGE_SIZE, q: q || undefined, role: role || undefined, active },
        { signal },
      ),
    [page, q, role, active, reload],
  );

  const setFilter = (patch: Record<string, string>) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v) next.set(k, v);
        else next.delete(k);
      }
      if (!('page' in patch)) next.delete('page');
      return next;
    });
  };

  const refresh = (msg: string) => {
    setMessage(msg);
    setReload((r) => r + 1);
  };

  return (
    <div className="space-y-6">
      <Card title="Add a user">
        <AddUserForm onCreated={refresh} />
      </Card>

      <Card title="Users">
        <div className="space-y-4 text-sm">
          <div aria-live="polite">
            {message && (
              <p
                role="status"
                className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-900"
              >
                {message}
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <form
              role="search"
              aria-label="Search users"
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                setFilter({ q: search.trim() });
              }}
            >
              <label className="block text-xs font-medium text-slate-600">
                Email or name
                <input
                  type="search"
                  className={`${inputClass} mt-1 w-64`}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  maxLength={254}
                />
              </label>
              <Button type="submit">Search</Button>
            </form>
            <label className="block text-xs font-medium text-slate-600">
              Role
              <select
                className={`${selectClass} mt-1 block`}
                value={role}
                onChange={(e) => setFilter({ role: e.target.value })}
              >
                <option value="">All roles</option>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABELS[r]}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-xs font-medium text-slate-600">
              Status
              <select
                className={`${selectClass} mt-1 block`}
                value={active}
                onChange={(e) => setFilter({ active: e.target.value })}
              >
                <option value="">Active and inactive</option>
                <option value="true">Active</option>
                <option value="false">Inactive</option>
              </select>
            </label>
          </div>

          {state.status === 'loading' && (
            <p role="status" className="text-slate-500">
              Loading users…
            </p>
          )}
          {state.status === 'error' && (
            <ErrorAlert error={state.error} title="Could not load users" />
          )}
          {state.status === 'success' &&
            (state.data.items.length === 0 ? (
              <EmptyState title="No users match these filters" icon={Users} />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <caption className="sr-only">Users</caption>
                    <thead>
                      <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                        <th scope="col" className="py-2 pr-4">
                          Email
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Name
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Role
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Status
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Signed in
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Last login
                        </th>
                        <th scope="col" className="py-2">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {state.data.items.map((u) => (
                        <UserRow
                          key={u.id}
                          user={u}
                          isSelf={u.id === currentUserId}
                          open={openId === u.id}
                          onToggle={() => setOpenId((id) => (id === u.id ? null : u.id))}
                          onSaved={(msg) => {
                            setOpenId(null);
                            refresh(msg);
                          }}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination
                  page={state.data.page}
                  pageSize={state.data.pageSize}
                  total={state.data.total}
                  onPage={(p) => setFilter({ page: String(p) })}
                />
              </>
            ))}
        </div>
      </Card>
    </div>
  );
}

type FieldErrors = Partial<Record<'email' | 'displayName' | 'role', string>>;

function AddUserForm({ onCreated }: { onCreated: (message: string) => void }) {
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const id = useId();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const parsed = userCreateRequestSchema.safeParse({
      email: email.trim(),
      role,
      ...(displayName.trim() ? { displayName: displayName.trim() } : {}),
    });
    if (!parsed.success) {
      const errors: FieldErrors = {};
      for (const issue of parsed.error.issues) {
        const key = issue.path[0];
        if (key === 'email') errors.email = 'Enter a valid email address.';
        else if (key === 'displayName') errors.displayName = 'Names are at most 120 characters.';
        else if (key === 'role') errors.role = 'Choose a role.';
      }
      setFieldErrors(errors);
      return;
    }
    setFieldErrors({});
    setBusy(true);
    try {
      const { user } = await api.users.create(parsed.data);
      setEmail('');
      setDisplayName('');
      setRole('viewer');
      onCreated(
        `${user.email} was added as ${ROLE_LABELS[user.role]}. They can sign in once the Cloudflare Access policy allows them.`,
      );
    } catch (err) {
      setError(plainUserError(toError(err), false));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} noValidate aria-label="Add a user" className="space-y-3 text-sm">
      <div
        id={`${id}-note`}
        className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sky-900"
      >
        <p>
          Adding someone here only sets their role in ExDomainVault. They must{' '}
          <strong>also be allowed by the Cloudflare Access policy</strong> to reach the app.
        </p>
        <p className="mt-1">
          Their identity is bound on first sign-in: the first time they sign in through Cloudflare
          Access with this email address, the account is linked to that identity.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <label className="block font-medium text-slate-700">
            Email
            <input
              type="email"
              className={`${inputClass} mt-1`}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              maxLength={254}
              autoComplete="off"
              required
              aria-invalid={fieldErrors.email ? true : undefined}
              aria-describedby={fieldErrors.email ? `${id}-email-error` : `${id}-note`}
            />
          </label>
          {fieldErrors.email && (
            <p id={`${id}-email-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.email}
            </p>
          )}
        </div>
        <div>
          <label className="block font-medium text-slate-700">
            Name (optional)
            <input
              className={`${inputClass} mt-1`}
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={120}
              aria-invalid={fieldErrors.displayName ? true : undefined}
              aria-describedby={fieldErrors.displayName ? `${id}-name-error` : undefined}
            />
          </label>
          {fieldErrors.displayName && (
            <p id={`${id}-name-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.displayName}
            </p>
          )}
        </div>
        <label className="block font-medium text-slate-700">
          Role
          <select
            className={`${selectClass} mt-1 block w-full`}
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABELS[r]}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && <ErrorAlert error={error} title="The user was not added" />}
      <Button type="submit" variant="primary" disabled={busy}>
        <UserPlus className="size-4" aria-hidden />
        Add user
      </Button>
    </form>
  );
}

function UserRow({
  user,
  isSelf,
  open,
  onToggle,
  onSaved,
}: {
  user: User;
  isSelf: boolean;
  open: boolean;
  onToggle: () => void;
  onSaved: (message: string) => void;
}) {
  const editorId = useId();
  const label = user.displayName ? `${user.displayName} (${user.email})` : user.email;
  return (
    <>
      <tr className={user.isActive ? '' : 'text-slate-500'}>
        <th scope="row" className="py-2 pr-4 text-left font-normal">
          <span className="break-all">{user.email}</span>
          {isSelf && (
            <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-700">
              You
            </span>
          )}
        </th>
        <td className="py-2 pr-4">{user.displayName ?? '—'}</td>
        <td className="py-2 pr-4">{ROLE_LABELS[user.role]}</td>
        <td className="py-2 pr-4">
          {user.isActive ? (
            <span className="text-emerald-700">Active</span>
          ) : (
            <span className="font-medium text-slate-600">Inactive</span>
          )}
        </td>
        <td className="py-2 pr-4">{user.signedIn ? 'Yes' : 'Not yet'}</td>
        <td className="py-2 pr-4 text-slate-600">
          {user.lastLoginAt ? formatDateTime(user.lastLoginAt) : 'Never'}
        </td>
        <td className="py-2 text-right">
          <Button
            onClick={onToggle}
            aria-expanded={open}
            aria-controls={open ? editorId : undefined}
            aria-label={`${open ? 'Close' : 'Manage'} ${user.email}`}
          >
            {open ? 'Close' : 'Manage'}
          </Button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} className="bg-slate-50 p-3">
            <UserEditor id={editorId} label={label} user={user} isSelf={isSelf} onSaved={onSaved} />
          </td>
        </tr>
      )}
    </>
  );
}

type Pending = { kind: 'role'; role: Role } | { kind: 'deactivate' } | null;

function UserEditor({
  id,
  label,
  user,
  isSelf,
  onSaved,
}: {
  id: string;
  label: string;
  user: User;
  isSelf: boolean;
  onSaved: (message: string) => void;
}) {
  const [name, setName] = useState(user.displayName ?? '');
  const [role, setRole] = useState<Role>(user.role);
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const fieldId = useId();

  const save = async (body: UserUpdateRequest, message: (u: User) => string) => {
    setBusy(true);
    setError(null);
    try {
      const { user: next } = await api.users.update(user.id, body);
      setPending(null);
      onSaved(message(next));
    } catch (err) {
      setPending(null);
      setError(plainUserError(toError(err), isSelf));
    } finally {
      setBusy(false);
    }
  };

  const trimmed = name.trim();
  const nameChanged = trimmed !== (user.displayName ?? '');

  return (
    <div id={id} role="group" aria-label={`Manage ${user.email}`} className="space-y-4 text-sm">
      {isSelf && (
        <p className="text-slate-600">
          This is your own account. You cannot change your own role or deactivate yourself; another
          administrator must do that.
        </p>
      )}

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void save({ displayName: trimmed === '' ? null : trimmed }, (u) =>
            u.displayName
              ? `${u.email} is now named ${u.displayName}.`
              : `${u.email}'s name was cleared.`,
          );
        }}
      >
        <label className="block font-medium text-slate-700" htmlFor={`${fieldId}-name`}>
          Display name
          <input
            id={`${fieldId}-name`}
            className={`${inputClass} mt-1 w-64`}
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={120}
          />
        </label>
        <Button type="submit" disabled={busy || !nameChanged}>
          Save name
        </Button>
      </form>

      <div className="flex flex-wrap items-end gap-2">
        <label className="block font-medium text-slate-700">
          Role
          <select
            className={`${selectClass} mt-1 block`}
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            disabled={isSelf || busy || pending !== null}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABELS[r]}
              </option>
            ))}
          </select>
        </label>
        <Button
          disabled={isSelf || busy || pending !== null || role === user.role}
          onClick={() => {
            setError(null);
            setPending({ kind: 'role', role });
          }}
        >
          Change role
        </Button>

        {user.isActive ? (
          <Button
            variant="danger"
            disabled={isSelf || busy || pending !== null}
            onClick={() => {
              setError(null);
              setPending({ kind: 'deactivate' });
            }}
          >
            Deactivate
          </Button>
        ) : (
          <Button
            disabled={busy || pending !== null}
            onClick={() => void save({ isActive: true }, (u) => `${u.email} was activated.`)}
          >
            Activate
          </Button>
        )}
      </div>

      {pending?.kind === 'role' && (
        <ConfirmPanel
          title={`Change the role of ${label} from ${ROLE_LABELS[user.role]} to ${ROLE_LABELS[pending.role]}?`}
          confirmLabel="Confirm role change"
          busy={busy}
          onCancel={() => setPending(null)}
          onConfirm={() =>
            void save({ role: pending.role }, (u) => `${u.email} is now ${ROLE_LABELS[u.role]}.`)
          }
        >
          {pending.role === 'admin'
            ? 'Administrators can manage users, scope, scan policies and settings.'
            : pending.role === 'asset_owner'
              ? 'Asset owners see only the assets assigned to them and those assets’ findings.'
              : 'Their permissions change on their next request.'}{' '}
          The change is recorded in the audit log.
        </ConfirmPanel>
      )}
      {pending?.kind === 'deactivate' && (
        <ConfirmPanel
          title={`Deactivate ${label}?`}
          confirmLabel="Confirm deactivation"
          danger
          busy={busy}
          onCancel={() => setPending(null)}
          onConfirm={() => void save({ isActive: false }, (u) => `${u.email} was deactivated.`)}
        >
          Their requests are refused from now on, even if Cloudflare Access still lets them in. You
          can activate them again later. The change is recorded in the audit log.
        </ConfirmPanel>
      )}

      {error && <ErrorAlert error={error} title="The change was not saved" />}
    </div>
  );
}
