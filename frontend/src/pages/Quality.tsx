import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function Quality() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Паспорта качества</h1>
      <Card>
        <CardHeader>
          <CardTitle>Проверки качества</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Здесь будут отображаться чек-листы и статусы качества по проектам.</p>
        </CardContent>
      </Card>
    </div>
  )
}
