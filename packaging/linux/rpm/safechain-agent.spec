Name:           safechain-agent
Version:        %{_version}
Release:        1%{?dist}
Summary:        Aikido Security SafeChain Agent - monitors and secures the software supply chain
License:        Proprietary
URL:            https://www.aikido.dev
Vendor:         Aikido Security BV

%description
SafeChain Agent monitors and secures the software supply chain by providing
real-time protection against supply chain attacks.

%install
mkdir -p %{buildroot}/opt/aikidosecurity/safechainagent/bin
mkdir -p %{buildroot}/var/log/aikidosecurity/safechainagent
mkdir -p %{buildroot}/var/run/aikidosecurity/safechainagent
mkdir -p %{buildroot}%{_unitdir}

install -m 755 %{_bindir_source}/safechain-agent %{buildroot}/opt/aikidosecurity/safechainagent/bin/safechain-agent
install -m 755 %{_bindir_source}/safechain-proxy %{buildroot}/opt/aikidosecurity/safechainagent/bin/safechain-proxy
install -m 644 %{_sourcedir}/safechain-agent.service %{buildroot}%{_unitdir}/safechain-agent.service

%files
%dir /opt/aikidosecurity
%dir /opt/aikidosecurity/safechainagent
%dir /opt/aikidosecurity/safechainagent/bin
%dir /var/log/aikidosecurity
%dir /var/log/aikidosecurity/safechainagent
%dir /var/run/aikidosecurity
%dir /var/run/aikidosecurity/safechainagent
/opt/aikidosecurity/safechainagent/bin/safechain-agent
/opt/aikidosecurity/safechainagent/bin/safechain-proxy
%{_unitdir}/safechain-agent.service

%pre
if systemctl is-active --quiet safechain-agent 2>/dev/null; then
    systemctl stop safechain-agent
fi

%post
systemctl daemon-reload
systemctl enable safechain-agent
systemctl start safechain-agent

%preun
if [ $1 -eq 0 ]; then
    systemctl stop safechain-agent 2>/dev/null || true
    systemctl disable safechain-agent 2>/dev/null || true
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl daemon-reload
    rm -rf /var/log/aikidosecurity/safechainagent
    rm -rf /var/run/aikidosecurity/safechainagent
    rmdir /var/log/aikidosecurity 2>/dev/null || true
    rmdir /var/run/aikidosecurity 2>/dev/null || true
    rmdir /opt/aikidosecurity/safechainagent/bin 2>/dev/null || true
    rmdir /opt/aikidosecurity/safechainagent 2>/dev/null || true
    rmdir /opt/aikidosecurity 2>/dev/null || true
fi

%changelog
