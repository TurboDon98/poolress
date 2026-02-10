import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const data = [
  { name: 'Иванов', load: 80 },
  { name: 'Петров', load: 45 },
  { name: 'Сидоров', load: 100 },
  { name: 'Смирнов', load: 20 },
  { name: 'Кузнецов', load: 60 },
  { name: 'Попов', load: 90 },
];

export default function Workload() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Загруженность ресурсов</h1>
      <Card>
        <CardHeader>
          <CardTitle>Текущая нагрузка (%)</CardTitle>
        </CardHeader>
        <CardContent className="pl-2">
          <div className="h-[400px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="name" className="text-sm" />
                <YAxis className="text-sm" />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))' }}
                  itemStyle={{ color: 'hsl(var(--foreground))' }}
                />
                <Bar dataKey="load" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
