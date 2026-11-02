import "./globals.css"

export const metadata = {
  title: "Sharma Dental AI",
  description: "AI Dental Clinic Receptionist",
  theme: "system",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-gray-900 antialiased">
        {children}
      </body>
    </html>
  )
}