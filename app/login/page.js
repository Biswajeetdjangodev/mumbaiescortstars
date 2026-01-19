import React, { Suspense } from 'react'
import dynamic from 'next/dynamic'

const LoginForm = dynamic(() => import('@/components/LoginForm'), {
  suspense: true,
})

const Login = () => {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  )
}

export default Login
