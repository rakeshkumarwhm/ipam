from .conftest import PW, login


def test_auth_required(client):
    assert client.get("/api/sections").status_code == 401


def test_bad_login_and_lockout(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 429


def test_logout_revokes_token(client):
    h = login(client)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    client.post("/api/auth/logout", headers=h)
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_subnet_flow_and_overlap(client):
    h = login(client)
    sec = client.post("/api/sections", json={"name": "DC1"}, headers=h).json()
    r = client.post("/api/subnets", json={"section_id": sec["id"], "cidr": "10.1.0.0/24"}, headers=h)
    assert r.status_code == 201
    sid = r.json()["id"]
    assert client.post("/api/subnets", json={"section_id": sec["id"], "cidr": "10.1.0.128/25"},
                       headers=h).status_code == 409
    assert client.post(f"/api/subnets/{sid}/addresses", json={"ip": "10.1.0.5", "hostname": "fw1"},
                       headers=h).status_code == 201
    assert client.post(f"/api/subnets/{sid}/addresses", json={"ip": "10.1.0.5"}, headers=h).status_code == 409
    assert client.post(f"/api/subnets/{sid}/addresses", json={"ip": "10.2.0.5"}, headers=h).status_code == 422
    u = client.get(f"/api/subnets/{sid}", headers=h).json()
    assert (u["total"], u["used"], u["free"], u["next_free"]) == (254, 1, 253, "10.1.0.1")


def test_section_permissions(client):
    a = login(client)
    sec = client.post("/api/sections", json={"name": "Secret"}, headers=a).json()
    sub = client.post("/api/subnets", json={"section_id": sec["id"], "cidr": "10.9.0.0/24"},
                      headers=a).json()
    v = login(client, "view")
    assert client.get(f"/api/subnets/{sub['id']}", headers=v).status_code == 403
    assert client.get("/api/sections", headers=v).json() == []
    users = {u["username"]: u["id"] for u in client.get("/api/users", headers=a).json()}
    client.put(f"/api/users/sections/{sec['id']}/permissions",
               json={"user_id": users["view"], "level": "write"}, headers=a)
    assert client.get(f"/api/subnets/{sub['id']}", headers=v).status_code == 200
    # viewer role can never write, even with a 'write' grant
    assert client.post(f"/api/subnets/{sub['id']}/addresses", json={"ip": "10.9.0.2"},
                       headers=v).status_code == 403


def test_admin_only(client):
    assert client.get("/api/users", headers=login(client, "op")).status_code == 403
    assert client.get("/api/audit", headers=login(client, "op")).status_code == 403


def test_csv_import_and_formula_export(client):
    h = login(client)
    sec = client.post("/api/sections", json={"name": "Imp"}, headers=h).json()
    csv_data = b"cidr,description\n10.5.0.0/24,=cmd()\nnot-a-cidr,x\n10.5.0.0/25,overlap\n"
    r = client.post(f"/api/sections/{sec['id']}/import", files={"file": ("s.csv", csv_data)}, headers=h)
    assert r.json()["created"] == 1 and len(r.json()["errors"]) == 2
    exp = client.get(f"/api/sections/{sec['id']}/export", headers=h).text
    assert "'=cmd()" in exp


def test_security_headers_and_no_docs(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/docs").status_code == 404


def test_forgot_and_reset_flow(client, monkeypatch, db_session):
    sent = {}
    monkeypatch.setattr("app.routers.auth.send_reset_email",
                        lambda to, link, minutes: sent.update(to=to, link=link))
    from app.models import User
    with db_session() as s:
        s.query(User).filter_by(username="op").one().email = "op@example.com"
        s.commit()
    # unknown address: identical response, nothing sent
    r1 = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r1.status_code == 202 and not sent
    r2 = client.post("/api/auth/forgot-password", json={"email": "op@example.com"})
    assert r2.status_code == 202 and r2.json() == r1.json() and sent["to"] == "op@example.com"
    token = sent["link"].split("#reset=")[1]
    old = login(client, "op")
    assert client.post("/api/auth/reset-password",
                       json={"token": token, "new_password": "weak"}).status_code == 422
    new_pw = "N3wStrongPassw0rd"
    assert client.post("/api/auth/reset-password",
                       json={"token": token, "new_password": new_pw}).status_code == 204
    assert client.get("/api/auth/me", headers=old).status_code == 401      # old sessions revoked
    assert client.post("/api/auth/reset-password",                          # single use
                       json={"token": token, "new_password": new_pw}).status_code == 400
    assert login(client, "op", new_pw)
