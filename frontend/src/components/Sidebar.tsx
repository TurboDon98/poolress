import { Link, useLocation } from "react-router-dom"
import { cn } from "@/lib/utils"
import { 
  LayoutDashboard, 
  FolderKanban, 
  Users, 
  ClipboardCheck, 
  BarChart3, 
  Settings, 
  LogOut 
} from "lucide-react"
import { useAuthStore } from "@/store/useAuthStore"

const navItems = [
  { icon: LayoutDashboard, label: "Главная", href: "/" },
  { icon: FolderKanban, label: "Банк проектов", href: "/projects" },
  { icon: Users, label: "Ресурсы", href: "/resources" },
  { icon: ClipboardCheck, label: "Паспорта качества", href: "/quality" },
  { icon: BarChart3, label: "Загруженность", href: "/workload" },
  { icon: Settings, label: "Настройки", href: "/settings" },
]

export default function Sidebar() {
  const location = useLocation()
  const logout = useAuthStore((state) => state.logout)

  return (
    <div className="flex w-64 flex-col border-r bg-card px-4 py-6 shadow-sm">
      <div className="mb-8 flex items-center gap-3 px-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <FolderKanban className="h-5 w-5" />
        </div>
        <span className="text-xl font-bold tracking-tight">TurboProject</span>
      </div>
      
      <nav className="flex-1 space-y-1">
        {navItems.map((item) => (
          <Link
            key={item.href}
            to={item.href}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-200",
              location.pathname === item.href 
                ? "bg-primary text-primary-foreground shadow-md" 
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:translate-x-1"
            )}
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </Link>
        ))}
      </nav>

      <div className="mt-auto border-t pt-4">
        <button 
          onClick={logout}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors"
        >
          <LogOut className="h-4 w-4" />
          Выход
        </button>
      </div>
    </div>
  )
}
