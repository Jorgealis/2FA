"""Repositorio de usuarios: Supabase si hay credenciales, si no un dict en memoria (plan B)."""
import os
import uuid

from dotenv import load_dotenv

load_dotenv()


class MemoryUserRepo:
    def __init__(self):
        self.users: dict[str, dict] = {}

    def create(self, email: str, password_hash: str) -> dict:
        if self.get_by_email(email):
            raise ValueError("El email ya existe")
        u = {"id": str(uuid.uuid4()), "email": email, "password_hash": password_hash,
             "mfa_status": "DISABLED", "totp_secret": None, "backup_codes": []}
        self.users[u["id"]] = u
        return dict(u)

    def get_by_email(self, email: str) -> dict | None:
        return next((dict(u) for u in self.users.values() if u["email"] == email), None)

    def get_by_id(self, user_id: str) -> dict | None:
        u = self.users.get(user_id)
        return dict(u) if u else None

    def update(self, user_id: str, **fields) -> None:
        self.users[user_id].update(fields)


class SupabaseUserRepo:
    def __init__(self, url: str, key: str):
        from supabase import create_client
        self.client = create_client(url, key)

    def _one(self, rows):
        return rows.data[0] if rows.data else None

    def create(self, email: str, password_hash: str) -> dict:
        if self.get_by_email(email):
            raise ValueError("El email ya existe")
        return self._one(self.client.table("users").insert(
            {"email": email, "password_hash": password_hash}).execute())

    def get_by_email(self, email: str) -> dict | None:
        return self._one(self.client.table("users").select("*").eq("email", email).execute())

    def get_by_id(self, user_id: str) -> dict | None:
        return self._one(self.client.table("users").select("*").eq("id", user_id).execute())

    def update(self, user_id: str, **fields) -> None:
        self.client.table("users").update(fields).eq("id", user_id).execute()


def build_repo():
    url, key = os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    if url and key:
        print("[repo] Usando Supabase")
        return SupabaseUserRepo(url, key)
    print("[repo] SUPABASE_URL/SUPABASE_KEY no definidos -> usando repositorio en memoria")
    return MemoryUserRepo()


repo = build_repo()
