import Home from '../Pages/Home';
import Services from '../Pages/Services';
import Login from '../Pages/Login';
import Signup from '../Pages/Signup';
import Contact from '../Pages/Contact';
import Doctors from '../Pages/Doctors/Doctors';
import DoctorDetails from '../Pages/Doctors/DoctorDetails';
import MyAccount from '../Dashboard/user-account/MyAccount';
import Dashboard from '../Dashboard/doctor-account/Dashboard';
import CheckoutSuccess from '../Pages/Doctors/CheckoutSuccess';

import { Routes, Route} from 'react-router-dom';
import ProtectedRoute from './ProtectedRoute';


const Routers = () => {
  return (
    <Routes>
      <Route path='/' element={<Home/>}/>
      <Route path='/home' element={<Home/>}/>
      <Route path='/doctors' element={<Doctors/>}/>
      <Route path='/doctors/:id' element={<DoctorDetails/>}/>
      <Route path='/login' element={<Login/>}/>
      <Route path='/register' element={<Signup/>}/>
      <Route path='/contact' element={<Contact/>}/>
      <Route path='/services' element={<Services/>}/>
      <Route path='/checkout-success' element={<CheckoutSuccess/>}/>
      <Route path='/users/profile/me' 
              element={
                <ProtectedRoute allowedRoles={['patient']}>
                  <MyAccount/>
                </ProtectedRoute>
              }/>
      <Route path='/doctors/profile/me' 
              element={
                <ProtectedRoute allowedRoles={['doctor']}>
                  <Dashboard/>
                </ProtectedRoute>
              }/>
    </Routes>
  );
}

export default Routers;

