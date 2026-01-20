import React, { Suspense } from 'react'
import dynamicImport from 'next/dynamic'

// Force dynamic rendering for registration page
export const dynamic = 'force-dynamic';

const RegistrationForm = dynamicImport(() => import('@/components/RegistrationForm'), {
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

