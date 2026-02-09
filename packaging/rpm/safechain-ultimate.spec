Name:           safechain-ultimate
Version:        %{_pkg_version}
Release:        1%{?dist}
Summary:        SafeChain Ultimate - Security Agent by Aikido Security

License:        AGPL-3.0-or-later
URL:            https://aikido.dev

AutoReqProv:    no

%description
SafeChain Ultimate is a security agent by Aikido Security that protects
your applications and infrastructure.

%install
mkdir -p %{buildroot}/opt/aikidosecurity/safechainultimate/bin
mkdir -p %{buildroot}/opt/aikidosecurity/safechainultimate/scripts
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/var/log/aikidosecurity/safechainultimate

install -m 755 %{_sourcedir}/safechain-ultimate %{buildroot}/opt/aikidosecurity/safechainultimate/bin/
install -m 755 %{_sourcedir}/safechain-ultimate-ui %{buildroot}/opt/aikidosecurity/safechainultimate/bin/
install -m 755 %{_sourcedir}/safechain-proxy %{buildroot}/opt/aikidosecurity/safechainultimate/bin/
install -m 755 %{_sourcedir}/uninstall %{buildroot}/opt/aikidosecurity/safechainultimate/scripts/
install -m 644 %{_sourcedir}/safechain-ultimate.service %{buildroot}/usr/lib/systemd/system/

%files
%dir /opt/aikidosecurity
%dir /opt/aikidosecurity/safechainultimate
%dir /opt/aikidosecurity/safechainultimate/bin
%dir /opt/aikidosecurity/safechainultimate/scripts
%dir /var/log/aikidosecurity
%dir /var/log/aikidosecurity/safechainultimate
%attr(755, root, root) /opt/aikidosecurity/safechainultimate/bin/safechain-ultimate
%attr(755, root, root) /opt/aikidosecurity/safechainultimate/bin/safechain-ultimate-ui
%attr(755, root, root) /opt/aikidosecurity/safechainultimate/bin/safechain-proxy
%attr(755, root, root) /opt/aikidosecurity/safechainultimate/scripts/uninstall
%attr(644, root, root) /usr/lib/systemd/system/safechain-ultimate.service

%pre
if systemctl is-active --quiet safechain-ultimate 2>/dev/null; then
    systemctl stop safechain-ultimate || true
fi

%post
systemctl daemon-reload
systemctl enable safechain-ultimate
systemctl start safechain-ultimate

echo ""
echo "SafeChain Ultimate has been installed successfully!"
echo "  Binaries: /opt/aikidosecurity/safechainultimate/bin"
echo "  Logs:     /var/log/aikidosecurity/safechainultimate"
echo ""
echo "The agent is now running as a systemd service."

%preun
if [ $1 -eq 0 ]; then
    if systemctl is-active --quiet safechain-ultimate 2>/dev/null; then
        systemctl stop safechain-ultimate || true
    fi
    systemctl disable safechain-ultimate 2>/dev/null || true
fi

%postun
systemctl daemon-reload
if [ $1 -eq 0 ]; then
    rm -rf /var/log/aikidosecurity/safechainultimate
    rmdir /var/log/aikidosecurity 2>/dev/null || true
    rmdir /opt/aikidosecurity 2>/dev/null || true
fi
