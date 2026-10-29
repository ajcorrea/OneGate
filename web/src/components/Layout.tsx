import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { useTheme } from "../theme";
import { Brand } from "./Logo";
import { Icon } from "./Icon";

function Item({ to, icon, label }: { to: string; icon: string; label: string }) {
  return (
    <NavLink to={to} end={to === "/"} className={({ isActive }) => "nav-item" + (isActive ? " active" : "")}>
      <Icon name={icon} />
      {label}
    </NavLink>
  );
}

/** Item do roteiro ainda não construído: aparece no menu para mostrar o caminho do MVP. */
function Soon({ icon, label, day }: { icon: string; label: string; day: string }) {
  return (
    <span className="nav-item soon" aria-disabled="true" title={`Previsto para o ${day} do cronograma`}>
      <Icon name={icon} />
      {label}
      <span className="soon-tag">{day}</span>
    </span>
  );
}

export function Layout() {
  const { me, logout, canAny } = useAuth();
  const { dark, toggle } = useTheme();
  if (!me) return null;
  const initials = me.name.split(/\s+/).map((p) => p[0]).slice(0, 2).join("").toUpperCase();

  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand />
        <nav className="nav" aria-label="Navegação principal">
          <span className="nav-section">Início</span>
          <Item to="/" icon="grid" label="Visão geral" />
          <span className="nav-section">Acesso à rede (AAA)</span>
          <Soon icon="shield" label="Painel AAA" day="dia 10" />
          {canAny("aaa.devices.view") && <Item to="/aaa/equipamentos" icon="router" label="Equipamentos" />}
          {canAny("aaa.rules.view") && <Item to="/aaa/objetos" icon="box" label="Objetos AAA" />}
          {canAny("aaa.rules.view") && <Item to="/aaa/regras" icon="shield" label="Regras de acesso" />}
          <span className="nav-section">Servidores (agente)</span>
          <Soon icon="server" label="Servidores" day="dia 5" />
          <Soon icon="terminal" label="Comandos em massa" day="dia 11" />
          <span className="nav-section">Administração</span>
          {canAny("admin.customers.view") && <Item to="/clientes" icon="building" label="Clientes" />}
          {canAny("admin.people.view") && <Item to="/pessoas" icon="users" label="Pessoas e acessos" />}
          {canAny("admin.people.view") && <Item to="/permissoes" icon="key" label="Permissões" />}
          {canAny("admin.audit.view") && <Item to="/auditoria" icon="file" label="Auditoria" />}
        </nav>
      </aside>

      <div className="main">
        <header className="topbar">
          <div style={{ flex: 1 }} />
          <button type="button" className="btn btn-icon" onClick={toggle} aria-label={dark ? "Mudar para tema claro" : "Mudar para tema escuro"}>
            <Icon name={dark ? "sun" : "moon"} />
          </button>
          <div className="row" style={{ gap: 10 }}>
            <span
              aria-hidden="true"
              style={{
                width: 36, height: 36, borderRadius: "50%", background: "var(--accent-soft)", color: "var(--accent-text)",
                fontWeight: 700, fontSize: 13, display: "flex", alignItems: "center", justifyContent: "center",
              }}
            >
              {initials}
            </span>
            <span style={{ display: "flex", flexDirection: "column" }}>
              <strong style={{ fontSize: 13 }}>{me.name}</strong>
              <span className="muted" style={{ fontSize: 11 }}>{me.is_admin ? "Admin global" : me.global ? "Acesso global" : "Acesso por cliente"} · {me.login}</span>
            </span>
          </div>
          <button type="button" className="btn btn-icon" onClick={() => void logout()} aria-label="Sair">
            <Icon name="logout" />
          </button>
        </header>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
