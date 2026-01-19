import React, { Suspense } from 'react'
import dynamic from 'next/dynamic'

const RegistrationForm = dynamic(() => import('@/components/RegistrationForm'), {
  suspense: true,
})

const Register = () => {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <RegistrationForm />
      </Suspense>
    </div>
  )
}

export default Register
