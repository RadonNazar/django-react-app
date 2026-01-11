import './App.css'

function App() {


  return (
      <div className="container mx-auto px-4 py-16">
          <h1 className="mb-4 text-center text-4xl font-bold tracking-tight text-heading md:text-5xl lg:text-6xl">
              Реєстрація користувача
          </h1>

          <div className="grid gap-6 justify-items-center ">

              <div className="w-full max-w-md ">
                  <label className="block mb-2 text-sm text-slate-600">
                      Електронна пошта
                  </label>
                  <input
                      className="w-full bg-transparent placeholder:text-slate-400
                        text-slate-700 text-sm border
                        border-slate-200 rounded-md px-3 py-2 transition
                        duration-300 ease focus:outline-none focus:border-slate-400
                        hover:border-slate-300 shadow-sm focus:shadow"
                      placeholder="Вкажіть пошту"/>
              </div>

              <div className="w-full max-w-md ">
                  <label className="block mb-2 text-sm text-slate-600">
                      Прізвище
                  </label>
                  <input
                      className="w-full bg-transparent placeholder:text-slate-400
                        text-slate-700 text-sm border
                        border-slate-200 rounded-md px-3 py-2 transition
                        duration-300 ease focus:outline-none focus:border-slate-400
                        hover:border-slate-300 shadow-sm focus:shadow"
                      placeholder="Вкажіть прізвище"/>
              </div>
          </div>


      </div>
  )
}

export default App
