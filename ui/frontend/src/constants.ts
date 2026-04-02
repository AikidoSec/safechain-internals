import npmIcon from "../assets/npm.svg";
import pypiIcon from "../assets/pypi.svg";
import vscodeIcon from "../assets/vscode.png";
import defaultIcon from "../assets/package-outline.svg";
import mavenIcon from "../assets/maven.svg";
import nugetIcon from "../assets/nuget.svg";
import chromeIcon from "../assets/chrome.svg";
import openVsxIcon from "../assets/open_vsx.png";
import skillsShIcon from "../assets/skills-sh.svg";

const TOOL_ICONS: Record<string, string> = {
  pypi: pypiIcon,
  vscode: vscodeIcon,
  npm: npmIcon,
  maven: mavenIcon,
  nuget: nugetIcon,
  chrome: chromeIcon,
  open_vsx: openVsxIcon,
  skills_sh: skillsShIcon,
};

export const getToolIcon = (tool: string) => {
  return TOOL_ICONS[tool.toLowerCase()] || defaultIcon;
};
