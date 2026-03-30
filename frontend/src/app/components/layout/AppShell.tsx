import { ReactNode, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";

type NavItem = {
  name: string;
  path?: string;
  external?: boolean;
  disabled?: boolean;
  badge?: string;
};

type AppShellProps = {
  children: ReactNode;
  title?: string;
  secondaryNavItems?: NavItem[];
  contextualActions?: ReactNode;
};

export default function AppShell({
  children,
  title = "Dashboard",
  secondaryNavItems = [],
  contextualActions,
}: AppShellProps) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const primaryNavItems: NavItem[] = useMemo(
    () => [
      { name: "Dashboard", path: "/dashboard" },
      { name: "Programs", path: "/programs", disabled: true, badge: "Soon" },
      { name: "Bounties", path: "/bounties", disabled: true, badge: "Soon" },
      { name: "Settings", path: "/settings", disabled: true, badge: "Soon" },
      {
        name: "Docs",
        path: "https://docs.grainlify.com",
        external: true,
      },
    ],
    [],
  );

  const isActiveRoute = (path?: string) => {
    if (!path || path.startsWith("http")) return false;
    return location.pathname === path || location.pathname.startsWith(`${path}/`);
  };

  const renderNavItem = (item: NavItem, mobile = false) => {
    const isActive = isActiveRoute(item.path);

    const baseClass = [
      "flex items-center justify-between rounded-md px-4 py-3 text-sm font-medium transition",
      "focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-400",
      mobile ? "w-full" : "",
      item.disabled
        ? "cursor-not-allowed opacity-50"
        : isActive
          ? "bg-white text-black shadow-sm"
          : "text-white hover:bg-gray-700",
    ].join(" ");

    if (item.disabled) {
      return (
        <div
          key={item.name}
          className={baseClass}
          aria-disabled="true"
          title={`${item.name} is not available yet`}
        >
          <span>{item.name}</span>
          {item.badge ? (
            <span className="ml-3 rounded-full bg-gray-700 px-2 py-1 text-xs text-white">
              {item.badge}
            </span>
          ) : null}
        </div>
      );
    }

    if (item.external && item.path) {
      return (
        <a
          key={item.name}
          href={item.path}
          target="_blank"
          rel="noreferrer"
          className={baseClass}
        >
          <span>{item.name}</span>
          <span className="ml-3 text-xs opacity-80">↗</span>
        </a>
      );
    }

    return (
      <Link
        key={item.name}
        to={item.path || "#"}
        className={baseClass}
        aria-current={isActive ? "page" : undefined}
        onClick={() => setMobileMenuOpen(false)}
      >
        <span>{item.name}</span>
        {item.badge ? (
          <span className="ml-3 rounded-full bg-gray-700 px-2 py-1 text-xs text-white">
            {item.badge}
          </span>
        ) : null}
      </Link>
    );
  };

  const breadcrumbs = useMemo(() => {
    const segments = location.pathname.split("/").filter(Boolean);
    if (segments.length <= 1) return [];

    return segments.map((segment, index) => {
      const path = `/${segments.slice(0, index + 1).join("/")}`;
      const label = segment.charAt(0).toUpperCase() + segment.slice(1);
      return { label, path };
    });
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen bg-gray-100">
      <aside className="hidden min-h-screen w-72 flex-col bg-gray-900 text-white md:flex">
        <div className="border-b border-gray-800 px-5 py-4">
          <div className="truncate text-lg font-bold">Grainlify Workspace</div>
          <div className="truncate text-sm text-gray-300">
            Very Long Organization Name Example
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-2 p-3" aria-label="Primary navigation">
          {primaryNavItems.map((item) => renderNavItem(item))}
        </nav>

        <div className="border-t border-gray-800 px-4 py-3 text-xs text-gray-400">
          Docs opens in a new tab
        </div>
      </aside>

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b bg-white md:hidden">
          <div className="flex items-center justify-between px-4 py-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="rounded-md border px-4 py-2 text-sm font-medium"
              aria-label="Open navigation menu"
            >
              Menu
            </button>
            <div className="truncate text-base font-semibold">Grainlify</div>
            <div className="min-w-[44px]" />
          </div>
        </header>

        {mobileMenuOpen ? (
          <div className="fixed inset-0 z-40 md:hidden">
            <button
              type="button"
              className="absolute inset-0 bg-black/40"
              aria-label="Close navigation overlay"
              onClick={() => setMobileMenuOpen(false)}
            />
            <aside className="absolute left-0 top-0 flex h-full w-80 max-w-[85vw] flex-col bg-gray-900 text-white shadow-xl">
              <div className="flex items-center justify-between border-b border-gray-800 px-4 py-4">
                <div>
                  <div className="font-bold">Grainlify</div>
                  <div className="max-w-[220px] truncate text-sm text-gray-300">
                    Very Long Organization Name Example
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className="rounded-md border border-gray-700 px-3 py-2 text-sm"
                  aria-label="Close navigation menu"
                >
                  Close
                </button>
              </div>

              <nav
                className="flex flex-1 flex-col gap-2 overflow-y-auto p-3"
                aria-label="Mobile primary navigation"
              >
                {primaryNavItems.map((item) => renderNavItem(item, true))}
              </nav>

              <div className="border-t border-gray-800 px-4 py-3 text-xs text-gray-400">
                Keep important actions visible outside overflow menus.
              </div>
            </aside>
          </div>
        ) : null}

        <div className="border-b bg-white px-4 py-4 md:px-6">
          {breadcrumbs.length > 0 ? (
            <nav
              className="mb-2 flex flex-wrap items-center gap-2 text-sm text-gray-500"
              aria-label="Breadcrumb"
            >
              <Link to="/dashboard" className="hover:text-gray-700">
                Dashboard
              </Link>
              {breadcrumbs.map((crumb, index) => (
                <span key={crumb.path} className="flex items-center gap-2">
                  <span>/</span>
                  {index === breadcrumbs.length - 1 ? (
                    <span className="font-medium text-gray-700">{crumb.label}</span>
                  ) : (
                    <Link to={crumb.path} className="hover:text-gray-700">
                      {crumb.label}
                    </Link>
                  )}
                </span>
              ))}
            </nav>
          ) : null}

          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
              <p className="text-sm text-gray-500">
                Responsive app shell for desktop and mobile navigation.
              </p>
            </div>

            {contextualActions ? (
              <div className="flex flex-wrap items-center gap-2">{contextualActions}</div>
            ) : null}
          </div>

          {secondaryNavItems.length > 0 ? (
            <div className="mt-4 flex flex-wrap gap-2" aria-label="Secondary navigation">
              {secondaryNavItems.map((item) => {
                const active = isActiveRoute(item.path);

                if (item.disabled) {
                  return (
                    <div
                      key={item.name}
                      className="rounded-md border border-dashed px-3 py-2 text-sm text-gray-400"
                      aria-disabled="true"
                    >
                      {item.name}
                    </div>
                  );
                }

                if (item.external && item.path) {
                  return (
                    <a
                      key={item.name}
                      href={item.path}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded-md border px-3 py-2 text-sm hover:bg-gray-50"
                    >
                      {item.name} ↗
                    </a>
                  );
                }

                return (
                  <Link
                    key={item.name}
                    to={item.path || "#"}
                    aria-current={active ? "page" : undefined}
                    className={`rounded-md border px-3 py-2 text-sm transition ${
                      active
                        ? "border-gray-900 bg-gray-900 text-white"
                        : "hover:bg-gray-50"
                    }`}
                  >
                    {item.name}
                  </Link>
                );
              })}
            </div>
          ) : null}
        </div>

        <main className="flex-1 p-4 md:p-6">{children}</main>
      </div>
    </div>
  );
}