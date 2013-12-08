Name: 		ip45d
Version: 	0.154
#Release:	1%{?dist}
Release:	1
Summary:	IP45 daemon

Group:		System Environment/Daemons
License:	GPL 
URL:		http://ip45.org
Source0:	http://ip45.org/packages/ip45d/%{name}-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

#BuildRequires:	
#Requires:	

%description
Client part of IP45 protocol. For more information visit http://ip45.org


%prep
%setup -q


%build
#%XXXconfigure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install prefix=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sysconfdir}/init.d/ip45d
%{_sbindir}/ip45d
# %doc

%changelog

