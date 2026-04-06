import type { BlockReason } from "./types";
import npmIcon from "../assets/npm.png";
import pypiIcon from "../assets/pypi.png";
import vscodeIcon from "../assets/vscode.png";
import defaultIcon from "../assets/package-outline.svg";
import mavenIcon from "../assets/maven.svg";
import nugetIcon from "../assets/nuget.svg";
import chromeIcon from "../assets/chrome.png";
import openVsxIcon from "../assets/open_vsx.png";
import skillsShIcon from "../assets/skills-sh.svg";

export const BLOCK_REASON_LABEL: Record<BlockReason, string> = {
  malware: "Malware",
  rejected: "Rejected By Policy",
  block_all: "All Installs Blocked",
  request_install: "Approval Required",
  new_package: "Too Recently Published",
};

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
