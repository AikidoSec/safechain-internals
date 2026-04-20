import { getToolIcon } from "../constants";
type EcosystemRow = {
  id: string;
  name: string;
  subtitle?: string;
  icon: string;
};

const ECOSYSTEMS: EcosystemRow[] = [
  { id: "npm", name: "NPM", icon: getToolIcon("npm") },
  { id: "pypi", name: "PyPI", icon: getToolIcon("pypi") },
  { id: "vscode", name: "VS Code Extensions", icon: getToolIcon("vscode") },
  {
    id: "open_vsx",
    name: "Open VSX",
    subtitle: "Cursor, Windsurf, Kiro extensions, …",
    icon: getToolIcon("open_vsx"),
  },
  { id: "maven", name: "Maven", icon: getToolIcon("maven") },
  { id: "nuget", name: "NuGet", icon: getToolIcon("nuget") },
  { id: "chrome", name: "Chrome Extensions", icon: getToolIcon("chrome") },
  { id: "skills_sh", name: "Skills.sh", icon: getToolIcon("skills_sh") },
];

export function ProtectedEcosystems() {
  return (
    <div className="protected-ecosystems">
      <h1>Protected Ecosystems</h1>
      <div className="protected-ecosystems-table-wrap">
        <table className="protected-ecosystems-table">
          <tbody>
            {ECOSYSTEMS.map((row) => (
              <tr key={row.id}>
                <td>
                  <img src={row.icon} alt="" className="protected-ecosystems-table__icon" aria-hidden />
                </td>
                <td>
                  <div className="protected-ecosystems-table__label-cell">
                    <span className="protected-ecosystems-table__name">{row.name}</span>
                    {row.subtitle && (
                      <span className="protected-ecosystems-table__subtitle">{row.subtitle}</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
