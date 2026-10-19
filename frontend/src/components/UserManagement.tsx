import { useEffect, useState } from "react";
import { createUser, deleteUser, fetchUsers, updateUserRole } from "../api";
import type { UserEntry } from "../api";
import { Card } from "./Card";
import { ConfirmDialog } from "./ConfirmDialog";
import { useToast } from "./Toast";
import "./UserManagement.css";

export function UserManagement() {
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"admin" | "analyst">("analyst");
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const { push } = useToast();

  function refetch() {
    fetchUsers()
      .then(setUsers)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load users"));
  }

  useEffect(refetch, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await createUser(username, password, role);
      setUsername("");
      setPassword("");
      refetch();
      push(`Created user ${username}`, "success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create user");
    }
  }

  async function handleDelete(target: string) {
    setPendingDelete(null);
    try {
      await deleteUser(target);
      refetch();
      push(`Removed user ${target}`, "success");
    } catch (err) {
      push(err instanceof Error ? err.message : "failed to remove user", "error");
    }
  }

  async function handleRoleChange(target: string, newRole: "admin" | "analyst") {
    try {
      await updateUserRole(target, newRole);
      refetch();
    } catch (err) {
      push(err instanceof Error ? err.message : "failed to change role", "error");
    }
  }

  return (
    <Card title="User management">
      {error && <p className="error-text">{error}</p>}
      <table className="user-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.username}>
              <td className="mono">{u.username}</td>
              <td>
                <select value={u.role} onChange={(e) => handleRoleChange(u.username, e.target.value as "admin" | "analyst")}>
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                </select>
              </td>
              <td>
                <button type="button" className="reject-button" onClick={() => setPendingDelete(u.username)}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <form onSubmit={handleCreate} className="user-form">
        <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <input
          placeholder="password (12+ chars)"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <select value={role} onChange={(e) => setRole(e.target.value as "admin" | "analyst")}>
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
        <button type="submit">Add user</button>
      </form>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Remove this user?"
        description={<p>{pendingDelete} will no longer be able to sign in.</p>}
        confirmLabel="Remove"
        onConfirm={() => pendingDelete && handleDelete(pendingDelete)}
        onCancel={() => setPendingDelete(null)}
      />
    </Card>
  );
}
