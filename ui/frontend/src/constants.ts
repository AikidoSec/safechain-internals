import npmIcon from "../assets/npm.svg";
import pypiIcon from "../assets/pypi.svg";
import vscodeIcon from "../assets/vscode.svg";
import defaultIcon from "../assets/package-outline.svg";
import mavenIcon from "../assets/maven.svg";
import nugetIcon from "../assets/nuget.svg";
import chromeIcon from "../assets/chrome.svg";
import openVsxIcon from "../assets/open_vsx.png";

const TOOL_ICONS: Record<string, string> = {
  pypi: pypiIcon,
  vscode: vscodeIcon,
  npm: npmIcon,
  maven: mavenIcon,
  nuget: nugetIcon,
  chrome: chromeIcon,
  open_vsx: openVsxIcon,
};

export const getToolIcon = (tool: string) => {
  return TOOL_ICONS[tool.toLowerCase()] || defaultIcon;
};
