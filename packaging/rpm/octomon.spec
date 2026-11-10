# RPM for octomon, built from the release tarball rather than from source:
# the static musl binary that every other Linux channel ships, so the same
# bytes reach Fedora, RHEL and openSUSE and the package depends on nothing.
#
#   rpmbuild -bb --target x86_64 \
#       --define "version 0.12.1" --define "_sourcedir $PWD" octomon.spec
#
# with octomon-<arch>-unknown-linux-musl.tar.xz in _sourcedir. The release
# number is 1 with no dist tag: one repository serves every distribution.

%global debug_package %{nil}
# The binary is already stripped by the release build; the brp scripts that
# would re-strip or scan for debuginfo have nothing to do and, on a build
# host that is not the target architecture, would fail.
%global __strip /bin/true
%global __os_install_post %{nil}
%global rust_target %{_target_cpu}-unknown-linux-musl

Name:           octomon
Version:        %{version}
Release:        1
Summary:        btop-style terminal dashboard for your network

License:        MIT OR Apache-2.0
URL:            https://octomon.dev
Source0:        https://github.com/securitypedant/octomon/releases/download/v%{version}/octomon-%{rust_target}.tar.xz

# Powers startup path discovery and the [m] hop monitor; everything else
# works without it.
Recommends:     traceroute
# Nothing dynamic: the binary is static.
AutoReqProv:    no

%description
A btop-style terminal dashboard for network health: per-target latency, loss
and jitter, per-process and per-remote bandwidth, Wi-Fi signal, DNS resolver
health, and a triage engine that names the failing layer (gateway, ISP path,
DNS, wide internet) instead of leaving graphs to interpret.

%prep
%setup -q -n octomon-%{rust_target}

%build
# Nothing to build: the tarball carries the release binary.

%install
install -Dm755 octomon %{buildroot}%{_bindir}/octomon
install -Dm644 README.md %{buildroot}%{_docdir}/octomon/README.md
install -Dm644 LICENSE-MIT %{buildroot}%{_licensedir}/octomon/LICENSE-MIT
install -Dm644 LICENSE-APACHE %{buildroot}%{_licensedir}/octomon/LICENSE-APACHE

%files
%{_bindir}/octomon
%doc %{_docdir}/octomon/README.md
%license %{_licensedir}/octomon/LICENSE-MIT
%license %{_licensedir}/octomon/LICENSE-APACHE
