import React, { useState } from "react";
import {
  UserOutlined,
  TeamOutlined,
  ArrowRightOutlined,
  ArrowLeftOutlined,
  CheckCircleOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import {
  Form,
  Input,
  Button,
  Card,
  Progress,
  Select,
  Checkbox,
  Row,
  Col,
  Typography,
  message,
  Space,
  Spin,
} from "antd";
import { studentAPI, teacherAPI } from "../services/api";

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;
const { TextArea } = Input;

const salesCourses = [
  "Sales Fundamentals",
  "Digital & Online Sales",
  "Retail & Tele Sales",
  "B2B & Corporate Sales",
  "Negotiation & Closing Deals",
  "CRM Tools (Salesforce, HubSpot)",
  "Body Language & Communication",
  "Customer Relationship Management",
];

const craCourses = [
  "Clinical Trial Fundamentals",
  "Good Clinical Practice (GCP)",
  "Pharmacovigilance",
  "Clinical Data Management",
  "Regulatory Affairs",
  "Biostatistics Basics",
  "Medical Documentation",
  "Research Ethics",
];

const studyStatuses = ["Intermediate", "Diploma", "UG", "PG", "BTech", "Other"];
const branches = ["CSE", "ECE", "EEE", "Mechanical", "Civil", "IT", "Biotech", "Pharmacy", "Management", "Other"];
const yearsOfStudy = ["1st Year", "2nd Year", "3rd Year", "4th Year", "5th Year"];
const educationOptions = ["Bachelors", "Masters", "PhD", "Diploma", "Other"];
const experienceOptions = ["0-1 years", "1-3 years", "3-5 years", "5-10 years", "10+ years"];
const languagesOptions = ["English", "Hindi", "Telugu", "Tamil", "Kannada", "Malayalam", "Marathi", "Other"];

const MultiRoleRegistration = () => {
  const [currentView, setCurrentView] = useState("landing");
  const [role, setRole] = useState(null);
  const [loading, setLoading] = useState(false);
  const [studentStep, setStudentStep] = useState(1);
  const [teacherStep, setTeacherStep] = useState(1);
  const [studentForm] = Form.useForm();
  const [teacherForm] = Form.useForm();

  const [studentData, setStudentData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    confirmPassword: "",
    phone: "",
    currentStatus: "",
    branch: "",
    studyYear: "",
    schoolCollege: "",
    city: "",
    programInterest: "",
    salesSelections: [],
    craSelections: [],
    agreeTerms: false,
  });

  const [teacherData, setTeacherData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    confirmPassword: "",
    phone: "",
    city: "",
    highestEducation: "",
    experienceRange: "",
    institution: "",
    subjectExpertise: "",
    linkedin: "",
    experiencePdfUrl: "",
    teachingMode: "",
    availability: "",
    expectedHourlyRate: "",
    languages: [],
    bio: "",
    agreeTerms: false,
  });

  const studentSteps = [
    { id: 1, title: "Basic Details" },
    { id: 2, title: "Academic Details" },
    { id: 3, title: "Program Interests" },
    { id: 4, title: "Review & Confirm" },
  ];

  const teacherSteps = [
    { id: 1, title: "Basic Details" },
    { id: 2, title: "Professional Profile" },
    { id: 3, title: "Teaching Details" },
    { id: 4, title: "Languages & Bio" },
    { id: 5, title: "Review & Confirm" },
  ];

  const [studentEmailVerified, setStudentEmailVerified] = useState(false);
  const [studentShowOtp, setStudentShowOtp] = useState(false);
  const [studentOtp, setStudentOtp] = useState(Array(6).fill(""));
  const [studentOtpLoading, setStudentOtpLoading] = useState(false);
  const [studentResendLoading, setStudentResendLoading] = useState(false);

  const [teacherEmailVerified, setTeacherEmailVerified] = useState(false);
  const [teacherShowOtp, setTeacherShowOtp] = useState(false);
  const [teacherOtp, setTeacherOtp] = useState(Array(6).fill(""));
  const [teacherOtpLoading, setTeacherOtpLoading] = useState(false);
  const [teacherResendLoading, setTeacherResendLoading] = useState(false);

  const calcProgress = (step, totalSteps) => Math.round(((step - 1) / (totalSteps - 1)) * 100);
  const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const validatePassword = (pwd) => ({
    length: pwd.length >= 8,
    uppercase: /[A-Z]/.test(pwd),
    lowercase: /[a-z]/.test(pwd),
    number: /[0-9]/.test(pwd),
    special: /[!@#$%^&*]/.test(pwd),
  });
  const validateUrl = (url) => {
    if (!url) return true;
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };
  const validatePhone = (phone) => /^[0-9]{8,15}$/.test(phone);

  const handleStudentOtpChange = (e, index) => {
    const val = e.target.value.slice(0, 1);
    if (!/^\d?$/.test(val)) return;
    const next = [...studentOtp];
    next[index] = val;
    setStudentOtp(next);
    if (val && index < 5) {
      document.getElementById(`student-otp-${index + 1}`)?.focus();
    }
  };

  const handleStudentSendOtp = async () => {
    const values = await studentForm.validateFields(["email", "password", "confirmPassword"]);
    
    if (!validateEmail(values.email)) {
      message.error("Please enter a valid email");
      return;
    }

    const pwdChecks = validatePassword(values.password);
    if (!Object.values(pwdChecks).every(Boolean)) {
      message.error("Password must be 8+ chars with uppercase, lowercase, number & special char");
      return;
    }

    if (values.password !== values.confirmPassword) {
      message.error("Passwords do not match");
      return;
    }

    try {
      setStudentOtpLoading(true);
      const response = await studentAPI.sendOtp({ email: values.email, password: values.password });
      if (response.data.success) {
        setStudentShowOtp(true);
        setStudentOtp(Array(6).fill(""));
        setStudentData({ ...studentData, ...values });
        message.success("OTP sent to your email!");
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Failed to send OTP");
    } finally {
      setStudentOtpLoading(false);
    }
  };

  const handleStudentVerifyOtp = async () => {
    const code = studentOtp.join("");
    if (code.length !== 6) {
      message.error("Enter full 6-digit OTP");
      return;
    }
    try {
      setStudentOtpLoading(true);
      const response = await studentAPI.verifyOtp({ email: studentData.email, otp: code });
      if (response.data.success) {
        setStudentEmailVerified(true);
        setStudentShowOtp(false);
        message.success("Email verified successfully!");
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Invalid or expired OTP");
    } finally {
      setStudentOtpLoading(false);
    }
  };

  const handleStudentResendOtp = async () => {
    try {
      setStudentResendLoading(true);
      await studentAPI.sendOtp({ email: studentData.email, password: studentData.password });
      message.success("OTP resent successfully!");
      setStudentOtp(Array(6).fill(""));
    } catch (error) {
      message.error("Failed to resend OTP");
    } finally {
      setStudentResendLoading(false);
    }
  };

  const handleTeacherOtpChange = (e, index) => {
    const val = e.target.value.slice(0, 1);
    if (!/^\d?$/.test(val)) return;
    const next = [...teacherOtp];
    next[index] = val;
    setTeacherOtp(next);
    if (val && index < 5) {
      document.getElementById(`teacher-otp-${index + 1}`)?.focus();
    }
  };

  const handleTeacherSendOtp = async () => {
    const values = await teacherForm.validateFields(["email", "password", "confirmPassword"]);
    
    if (!validateEmail(values.email)) {
      message.error("Please enter a valid email");
      return;
    }

    const pwdChecks = validatePassword(values.password);
    if (!Object.values(pwdChecks).every(Boolean)) {
      message.error("Password must be 8+ chars with uppercase, lowercase, number & special char");
      return;
    }

    if (values.password !== values.confirmPassword) {
      message.error("Passwords do not match");
      return;
    }

    try {
      setTeacherOtpLoading(true);
      const response = await teacherAPI.sendOtp({ email: values.email, password: values.password });
      if (response.data.success) {
        setTeacherShowOtp(true);
        setTeacherOtp(Array(6).fill(""));
        setTeacherData({ ...teacherData, ...values });
        message.success("OTP sent to your email!");
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Failed to send OTP");
    } finally {
      setTeacherOtpLoading(false);
    }
  };

  const handleTeacherVerifyOtp = async () => {
    const code = teacherOtp.join("");
    if (code.length !== 6) {
      message.error("Enter full 6-digit OTP");
      return;
    }
    try {
      setTeacherOtpLoading(true);
      const response = await teacherAPI.verifyOtp({ email: teacherData.email, otp: code });
      if (response.data.success) {
        setTeacherEmailVerified(true);
        setTeacherShowOtp(false);
        message.success("Email verified successfully!");
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Invalid or expired OTP");
    } finally {
      setTeacherOtpLoading(false);
    }
  };

  const handleTeacherResendOtp = async () => {
    try {
      setTeacherResendLoading(true);
      await teacherAPI.sendOtp({ email: teacherData.email, password: teacherData.password });
      message.success("OTP resent successfully!");
      setTeacherOtp(Array(6).fill(""));
    } catch (error) {
      message.error("Failed to resend OTP");
    } finally {
      setTeacherResendLoading(false);
    }
  };

  const onStudentNext = async () => {
    try {
      const values = await studentForm.validateFields();

      if (studentStep === 1) {
        const pwdChecks = validatePassword(values.password);
        if (!Object.values(pwdChecks).every(Boolean)) {
          message.error("Password must be 8+ chars with uppercase, lowercase, number & special char");
          return;
        }
        if (values.password !== values.confirmPassword) {
          message.error("Passwords do not match");
          return;
        }
      }

      if (studentStep === 2) {
        if (!validatePhone(values.phone)) {
          message.error("Enter a valid phone number (8-15 digits)");
          return;
        }
        if (["UG", "PG", "BTech"].includes(values.currentStatus)) {
          if (!values.branch || !values.studyYear) {
            message.error("Please select branch & year if UG/PG/BTech");
            return;
          }
        }
      }

      setStudentData({ ...studentData, ...values });
      if (studentStep < 4) {
        setStudentStep(studentStep + 1);
      }
    } catch {
      message.error("Please fill all required fields correctly");
    }
  };

  const onTeacherNext = async () => {
    try {
      const values = await teacherForm.validateFields();

      if (teacherStep === 1) {
        const pwdChecks = validatePassword(values.password);
        if (!Object.values(pwdChecks).every(Boolean)) {
          message.error("Password must be 8+ chars with uppercase, lowercase, number & special char");
          return;
        }
        if (values.password !== values.confirmPassword) {
          message.error("Passwords do not match");
          return;
        }
      }

      if (teacherStep === 2) {
        if (!validatePhone(values.phone)) {
          message.error("Enter a valid phone number (8-15 digits)");
          return;
        }
      }

      if (teacherStep === 3) {
        if (values.linkedin && !validateUrl(values.linkedin)) {
          message.error("Enter a valid LinkedIn URL");
          return;
        }
        if (values.experiencePdfUrl && !validateUrl(values.experiencePdfUrl)) {
          message.error("Enter a valid Experience PDF URL");
          return;
        }
      }

      setTeacherData({ ...teacherData, ...values });
      if (teacherStep < 5) {
        setTeacherStep(teacherStep + 1);
      }
    } catch {
      message.error("Please fill all required fields correctly");
    }
  };

  const onStudentSubmit = async () => {
    if (!studentEmailVerified) {
      message.error("Please verify your email before submitting");
      return;
    }
    try {
      await studentForm.validateFields();
      if (!studentData.agreeTerms) {
        message.error("You must accept terms and conditions");
        return;
      }

      setLoading(true);
      const payload = {
        firstName: studentData.firstName,
        lastName: studentData.lastName,
        email: studentData.email,
        password: studentData.password,
        phone: studentData.phone,
        currentStatus: studentData.currentStatus,
        branch: studentData.branch,
        studyYear: studentData.studyYear,
        schoolCollege: studentData.schoolCollege,
        city: studentData.city,
        programInterest: studentData.programInterest,
        salesSelections: studentData.salesSelections || [],
        craSelections: studentData.craSelections || [],
        agreeTerms: studentData.agreeTerms
      };
      const response = await studentAPI.register(payload);
      if (response.data.success) {
        message.success("Student registration completed successfully!");
        setTimeout(() => setCurrentView("success"), 1000);
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const onTeacherSubmit = async () => {
    if (!teacherEmailVerified) {
      message.error("Please verify your email before submitting");
      return;
    }
    try {
      if (!teacherData.agreeTerms) {
        message.error("You must accept terms and conditions");
        return;
      }

      setLoading(true);
      const payload = {
        firstName: teacherData.firstName,
        lastName: teacherData.lastName,
        email: teacherData.email,
        password: teacherData.password,
        phone: teacherData.phone,
        city: teacherData.city,
        highestEducation: teacherData.highestEducation,
        experienceRange: teacherData.experienceRange,
        institution: teacherData.institution,
        subjectExpertise: teacherData.subjectExpertise,
        linkedin: teacherData.linkedin,
        experiencePdfUrl: teacherData.experiencePdfUrl,
        teachingMode: teacherData.teachingMode,
        availability: teacherData.availability,
        expectedHourlyRate: teacherData.expectedHourlyRate,
        languages: teacherData.languages,
        bio: teacherData.bio,
        agreeTerms: teacherData.agreeTerms
      };
      const response = await teacherAPI.register(payload);
      if (response.data.success) {
        message.success("Teacher registration completed successfully!");
        setTimeout(() => setCurrentView("success"), 1000);
      }
    } catch (error) {
      message.error(error.response?.data?.message || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const renderStudentFields = () => {
    switch (studentStep) {
      case 1:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="firstName" label="First Name" rules={[{ required: true, message: "Please enter first name" }]}>
              <Input size="large" placeholder="Enter first name" />
            </Form.Item>
            <Form.Item name="lastName" label="Last Name" rules={[{ required: true, message: "Please enter last name" }]}>
              <Input size="large" placeholder="Enter last name" />
            </Form.Item>
            <Form.Item name="email" label="Email" rules={[{ required: true, message: "Please enter email" }, { type: "email", message: "Please enter valid email" }]}>
              <Input size="large" placeholder="Enter email" disabled={studentShowOtp || studentEmailVerified} />
            </Form.Item>
            <Form.Item name="password" label="Password" rules={[{ required: true, message: "Please enter password" }]} extra="Use 8+ chars with uppercase, lowercase, number and special character">
              <Input.Password size="large" placeholder="Enter password" disabled={studentShowOtp || studentEmailVerified} />
            </Form.Item>
            <Form.Item name="confirmPassword" label="Confirm Password" rules={[{ required: true, message: "Please confirm password" }]}>
              <Input.Password size="large" placeholder="Confirm password" disabled={studentShowOtp || studentEmailVerified} />
            </Form.Item>
          </Space>
        );

      case 2:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="phone" label="Phone Number" rules={[{ required: true, message: "Please enter phone number" }]}>
              <Input size="large" placeholder="Enter phone number" />
            </Form.Item>
            <Form.Item name="currentStatus" label="Current Studying Status" rules={[{ required: true, message: "Please select status" }]}>
              <Select size="large" placeholder="Select status">
                {studyStatuses.map((s) => (<Option key={s} value={s}>{s}</Option>))}
              </Select>
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(prev, curr) => prev.currentStatus !== curr.currentStatus}>
              {({ getFieldValue }) =>
                ["UG", "PG", "BTech"].includes(getFieldValue("currentStatus")) ? (
                  <Row gutter={16}>
                    <Col span={12}>
                      <Form.Item name="branch" label="Branch" rules={[{ required: true, message: "Please select branch" }]}>
                        <Select size="large" placeholder="Select branch">
                          {branches.map((b) => (<Option key={b} value={b}>{b}</Option>))}
                        </Select>
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <Form.Item name="studyYear" label="Year of Study" rules={[{ required: true, message: "Please select year" }]}>
                        <Select size="large" placeholder="Select year">
                          {yearsOfStudy.map((y) => (<Option key={y} value={y}>{y}</Option>))}
                        </Select>
                      </Form.Item>
                    </Col>
                  </Row>
                ) : null
              }
            </Form.Item>
            <Form.Item name="schoolCollege" label="School / College Name" rules={[{ required: true, message: "Please enter school/college name" }]}>
              <Input size="large" placeholder="Enter school/college name" />
            </Form.Item>
          </Space>
        );

      case 3:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="city" label="City" rules={[{ required: true, message: "Please enter city" }]}>
              <Input size="large" placeholder="Enter city" />
            </Form.Item>
            <Form.Item name="programInterest" label="Program Interested In" rules={[{ required: true, message: "Please select program" }]}>
              <Select size="large" placeholder="Select program">
                <Option value="Sales Courses">Sales Courses</Option>
                <Option value="CRA Clinical Research Courses">CRA Clinical Research Courses</Option>
                <Option value="Both Sales and CRA">Both Sales and CRA</Option>
              </Select>
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(prev, curr) => prev.programInterest !== curr.programInterest}>
              {({ getFieldValue }) => {
                const program = getFieldValue("programInterest");
                return (
                  <>
                    {(program === "Sales Courses" || program === "Both Sales and CRA") && (
                      <Form.Item name="salesSelections" label="Sales Courses (select any)">
                        <Checkbox.Group style={{ width: "100%" }}>
                          <Row gutter={[8, 8]}>
                            {salesCourses.map((course) => (
                              <Col span={12} key={course}><Checkbox value={course}>{course}</Checkbox></Col>
                            ))}
                          </Row>
                        </Checkbox.Group>
                      </Form.Item>
                    )}
                    {(program === "CRA Clinical Research Courses" || program === "Both Sales and CRA") && (
                      <Form.Item name="craSelections" label="CRA Clinical Research Courses (select any)">
                        <Checkbox.Group style={{ width: "100%" }}>
                          <Row gutter={[8, 8]}>
                            {craCourses.map((course) => (
                              <Col span={12} key={course}><Checkbox value={course}>{course}</Checkbox></Col>
                            ))}
                          </Row>
                        </Checkbox.Group>
                      </Form.Item>
                    )}
                  </>
                );
              }}
            </Form.Item>
          </Space>
        );

      case 4:
        return (
          <Space direction="vertical" size="large" style={{ width: "100%" }}>
            <div>
              <Title level={5} className="student-theme-color">Review Your Details</Title>
              <Row gutter={[16, 8]} style={{ marginTop: 16 }}>
                <Col span={12}><Text strong>Name:</Text> <Text>{studentData.firstName} {studentData.lastName}</Text></Col>
                <Col span={12}><Text strong>Email:</Text> <Text>{studentData.email}</Text></Col>
                <Col span={12}><Text strong>Phone:</Text> <Text>{studentData.phone}</Text></Col>
                <Col span={12}><Text strong>Status:</Text> <Text>{studentData.currentStatus}</Text></Col>
                <Col span={12}><Text strong>Branch:</Text> <Text>{studentData.branch || "-"}</Text></Col>
                <Col span={12}><Text strong>Year:</Text> <Text>{studentData.studyYear || "-"}</Text></Col>
                <Col span={12}><Text strong>School/College:</Text> <Text>{studentData.schoolCollege}</Text></Col>
                <Col span={12}><Text strong>City:</Text> <Text>{studentData.city}</Text></Col>
                <Col span={24}><Text strong>Program:</Text> <Text>{studentData.programInterest}</Text></Col>
                <Col span={24}><Text strong>Sales Courses:</Text> <Text>{studentData.salesSelections?.length ? studentData.salesSelections.join(", ") : "-"}</Text></Col>
                <Col span={24}><Text strong>CRA Courses:</Text> <Text>{studentData.craSelections?.length ? studentData.craSelections.join(", ") : "-"}</Text></Col>
                <Col span={24}><Text strong>Email verification: </Text><Text type={studentEmailVerified ? "success" : "warning"}>{studentEmailVerified ? "Verified ✅" : "Not verified"}</Text></Col>
              </Row>
              <Row style={{ marginTop: 12 }}>
                <Col span={24}>
                  {!studentEmailVerified && !studentShowOtp && (
                    <Button type="primary" onClick={handleStudentSendOtp} loading={studentOtpLoading}>Send OTP</Button>
                  )}
                  {studentShowOtp && !studentEmailVerified && (
                    <>
                      <div style={{ display: "flex", gap: 8, margin: "12px 0" }}>
                        {studentOtp.map((digit, i) => (
                          <Input key={i} id={`student-otp-${i}`} value={digit} onChange={(e) => handleStudentOtpChange(e, i)} maxLength={1} style={{ width: 40, textAlign: "center" }} />
                        ))}
                      </div>
                      <Space>
                        <Button type="primary" onClick={handleStudentVerifyOtp} loading={studentOtpLoading}>Verify</Button>
                        <Button onClick={handleStudentResendOtp} loading={studentResendLoading}>Resend OTP</Button>
                      </Space>
                    </>
                  )}
                </Col>
              </Row>
            </div>
            <Card size="small" className="student-terms-card">
              <Paragraph style={{ margin: 0, fontSize: 12 }}>
                <Text strong>Terms & Conditions:</Text> By registering, you confirm all details are correct and consent to receive communications.
              </Paragraph>
            </Card>
            <Form.Item name="agreeTerms" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("You must accept terms")) }]}>
              <Checkbox onChange={(e) => setStudentData({ ...studentData, agreeTerms: e.target.checked })}>
                I have read and agree to the terms and conditions <Text type="danger">*</Text>
              </Checkbox>
            </Form.Item>
            <Button type="primary" size="large" block icon={loading ? <LoadingOutlined /> : <CheckCircleOutlined />} onClick={onStudentSubmit} loading={loading} disabled={!studentEmailVerified} className="student-submit-btn">
              {loading ? "Registering..." : "Register as Student"}
            </Button>
          </Space>
        );

      default:
        return null;
    }
  };

  const renderTeacherFields = () => {
    switch (teacherStep) {
      case 1:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="firstName" label="First Name" rules={[{ required: true, message: "Please enter first name" }]}>
              <Input size="large" placeholder="Enter first name" />
            </Form.Item>
            <Form.Item name="lastName" label="Last Name" rules={[{ required: true, message: "Please enter last name" }]}>
              <Input size="large" placeholder="Enter last name" />
            </Form.Item>
            <Form.Item name="email" label="Email" rules={[{ required: true, message: "Please enter email" }, { type: "email", message: "Please enter valid email" }]}>
              <Input size="large" placeholder="Enter email" disabled={teacherShowOtp || teacherEmailVerified} />
            </Form.Item>
            <Form.Item name="password" label="Password" rules={[{ required: true, message: "Please enter password" }]} extra="Use 8+ chars with uppercase, lowercase, number and special character">
              <Input.Password size="large" placeholder="Enter password" disabled={teacherShowOtp || teacherEmailVerified} />
            </Form.Item>
            <Form.Item name="confirmPassword" label="Confirm Password" rules={[{ required: true, message: "Please confirm password" }]}>
              <Input.Password size="large" placeholder="Confirm password" disabled={teacherShowOtp || teacherEmailVerified} />
            </Form.Item>
          </Space>
        );

      case 2:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="phone" label="Phone Number" rules={[{ required: true, message: "Please enter phone number" }]}>
              <Input size="large" placeholder="Enter phone number" />
            </Form.Item>
            <Form.Item name="city" label="City" rules={[{ required: true, message: "Please enter city" }]}>
              <Input size="large" placeholder="Enter city" />
            </Form.Item>
            <Form.Item name="highestEducation" label="Highest Education" rules={[{ required: true, message: "Please select education" }]}>
              <Select size="large" placeholder="Select education">
                {educationOptions.map((e) => (<Option key={e} value={e}>{e}</Option>))}
              </Select>
            </Form.Item>
            <Form.Item name="experienceRange" label="Total Experience" rules={[{ required: true, message: "Please select experience" }]}>
              <Select size="large" placeholder="Select experience">
                {experienceOptions.map((e) => (<Option key={e} value={e}>{e}</Option>))}
              </Select>
            </Form.Item>
            <Form.Item name="institution" label="Current / Last Institution" rules={[{ required: true, message: "Please enter institution" }]}>
              <Input size="large" placeholder="Enter institution" />
            </Form.Item>
          </Space>
        );

      case 3:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="subjectExpertise" label="Subject Expertise" rules={[{ required: true, message: "Please enter subject expertise" }]}>
              <Input size="large" placeholder="Enter subject expertise" />
            </Form.Item>
            <Form.Item name="linkedin" label="LinkedIn Profile URL">
              <Input size="large" placeholder="https://www.linkedin.com/in/username" />
            </Form.Item>
            <Form.Item name="experiencePdfUrl" label="Experience PDF URL">
              <Input size="large" placeholder="https://example.com/experience.pdf" />
            </Form.Item>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="teachingMode" label="Preferred Mode" rules={[{ required: true, message: "Please select mode" }]}>
                  <Select size="large" placeholder="Select mode">
                    <Option value="Online">Online</Option>
                    <Option value="Offline">Offline</Option>
                    <Option value="Hybrid">Hybrid</Option>
                  </Select>
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="expectedHourlyRate" label="Expected Hourly Rate (INR)">
                  <Input size="large" placeholder="e.g. 800" />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item name="availability" label="Availability (Days & Time)" rules={[{ required: true, message: "Please enter availability" }]}>
              <Input size="large" placeholder="e.g. Mon-Fri, 6pm - 9pm" />
            </Form.Item>
          </Space>
        );

      case 4:
        return (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Form.Item name="languages" label="Languages Spoken" rules={[{ required: true, message: "Please select at least one language" }]}>
              <Checkbox.Group style={{ width: "100%" }}>
                <Row gutter={[8, 8]}>
                  {languagesOptions.map((lang) => (
                    <Col span={12} key={lang}><Checkbox value={lang}>{lang}</Checkbox></Col>
                  ))}
                </Row>
              </Checkbox.Group>
            </Form.Item>
            <Form.Item name="bio" label="Short Bio" rules={[{ required: true, message: "Please add a short bio" }]}>
              <TextArea rows={4} placeholder="Briefly describe your teaching style and experience..." />
            </Form.Item>
          </Space>
        );

      case 5:
        return (
          <Space direction="vertical" size="large" style={{ width: "100%" }}>
            <div>
              <Title level={5} className="teacher-theme-color">Review Your Details</Title>
              <Row gutter={[16, 8]} style={{ marginTop: 16 }}>
                <Col span={12}><Text strong>Name:</Text> <Text>{teacherData.firstName} {teacherData.lastName}</Text></Col>
                <Col span={12}><Text strong>Email:</Text> <Text>{teacherData.email}</Text></Col>
                <Col span={12}><Text strong>Phone:</Text> <Text>{teacherData.phone}</Text></Col>
                <Col span={12}><Text strong>City:</Text> <Text>{teacherData.city}</Text></Col>
                <Col span={12}><Text strong>Education:</Text> <Text>{teacherData.highestEducation}</Text></Col>
                <Col span={12}><Text strong>Experience:</Text> <Text>{teacherData.experienceRange}</Text></Col>
                <Col span={12}><Text strong>Institution:</Text> <Text>{teacherData.institution}</Text></Col>
                <Col span={12}><Text strong>Subject:</Text> <Text>{teacherData.subjectExpertise}</Text></Col>
                <Col span={12}><Text strong>Mode:</Text> <Text>{teacherData.teachingMode}</Text></Col>
                <Col span={12}><Text strong>Rate:</Text> <Text>{teacherData.expectedHourlyRate || "-"}</Text></Col>
                <Col span={24}><Text strong>Availability:</Text> <Text>{teacherData.availability}</Text></Col>
                <Col span={24}><Text strong>LinkedIn:</Text> <Text>{teacherData.linkedin || "-"}</Text></Col>
                <Col span={24}><Text strong>Experience PDF:</Text> <Text>{teacherData.experiencePdfUrl || "-"}</Text></Col>
                <Col span={24}><Text strong>Languages:</Text> <Text>{teacherData.languages?.length ? teacherData.languages.join(", ") : "-"}</Text></Col>
                <Col span={24}><Text strong>Bio:</Text> <Text>{teacherData.bio || "-"}</Text></Col>
                <Col span={24}><Text strong>Email verification: </Text><Text type={teacherEmailVerified ? "success" : "warning"}>{teacherEmailVerified ? "Verified ✅" : "Not verified"}</Text></Col>
              </Row>
              <Row style={{ marginTop: 12 }}>
                <Col span={24}>
                  {!teacherEmailVerified && !teacherShowOtp && (
                    <Button type="primary" onClick={handleTeacherSendOtp} loading={teacherOtpLoading}>Send OTP</Button>
                  )}
                  {teacherShowOtp && !teacherEmailVerified && (
                    <>
                      <div style={{ display: "flex", gap: 8, margin: "12px 0" }}>
                        {teacherOtp.map((digit, i) => (
                          <Input key={i} id={`teacher-otp-${i}`} value={digit} onChange={(e) => handleTeacherOtpChange(e, i)} maxLength={1} style={{ width: 40, textAlign: "center" }} />
                        ))}
                      </div>
                      <Space>
                        <Button type="primary" onClick={handleTeacherVerifyOtp} loading={teacherOtpLoading}>Verify</Button>
                        <Button onClick={handleTeacherResendOtp} loading={teacherResendLoading}>Resend OTP</Button>
                      </Space>
                    </>
                  )}
                </Col>
              </Row>
            </div>
            <Card size="small" className="teacher-terms-card">
              <Paragraph style={{ margin: 0, fontSize: 12 }}>
                <Text strong>Terms & Conditions:</Text> By registering, you confirm the authenticity of your information and agree to platform guidelines.
              </Paragraph>
            </Card>
            <Form.Item name="agreeTerms" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("You must accept terms")) }]}>
              <Checkbox onChange={(e) => setTeacherData({ ...teacherData, agreeTerms: e.target.checked })}>
                I have read and agree to the terms and conditions <Text type="danger">*</Text>
              </Checkbox>
            </Form.Item>
            <Button type="primary" size="large" block icon={loading ? <LoadingOutlined /> : <CheckCircleOutlined />} onClick={onTeacherSubmit} loading={loading} disabled={!teacherEmailVerified} className="teacher-submit-btn">
              {loading ? "Registering..." : "Register as Teacher"}
            </Button>
          </Space>
        );

      default:
        return null;
    }
  };

  if (currentView === "landing") {
    return (
      <div className="landing-container">
        <Row gutter={24} justify="center" style={{ maxWidth: 1200, margin: "0 auto" }}>
          <Col xs={24} md={12}>
            <Card hoverable className="role-card student-card" onClick={() => { setRole("Student"); setCurrentView("student"); }}>
              <Space direction="vertical" size="large" style={{ width: "100%" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                  <div className="icon-wrapper student-icon">
                    <UserOutlined style={{ fontSize: 32 }} />
                  </div>
                  <div>
                    <Title level={3} style={{ margin: 0, color: "white" }}>Register as Student</Title>
                    <Text style={{ color: "rgba(255, 255, 255, 0.8)" }}>Create your learning profile, explore courses and programs.</Text>
                  </div>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <Text style={{ color: "rgba(255, 255, 255, 0.7)" }}>4 steps · 3 minutes</Text>
                  <ArrowRightOutlined className="arrow-icon" style={{ color: "#818cf8" }} />
                </div>
              </Space>
            </Card>
          </Col>
          <Col xs={24} md={12}>
            <Card hoverable className="role-card teacher-card" onClick={() => { setRole("Teacher"); setCurrentView("teacher"); }}>
              <Space direction="vertical" size="large" style={{ width: "100%" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                  <div className="icon-wrapper teacher-icon">
                    <TeamOutlined style={{ fontSize: 32 }} />
                  </div>
                  <div>
                    <Title level={3} style={{ margin: 0, color: "white" }}>Register as Teacher</Title>
                    <Text style={{ color: "rgba(255, 255, 255, 0.8)" }}>Showcase your expertise and start teaching motivated learners.</Text>
                  </div>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <Text style={{ color: "rgba(255, 255, 255, 0.7)" }}>5 steps · Profile-ready</Text>
                  <ArrowRightOutlined className="arrow-icon" style={{ color: "#34d399" }} />
                </div>
              </Space>
            </Card>
          </Col>
        </Row>
      </div>
    );
  }

  if (currentView === "student") {
    const progress = calcProgress(studentStep, studentSteps.length);
    return (
      <div className="form-container student-form-bg">
        <Spin spinning={loading} size="large">
          <Card className="form-card student-form-card" style={{ maxWidth: 700, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
              <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => { setCurrentView("landing"); setStudentStep(1); studentForm.resetFields(); setStudentEmailVerified(false); setStudentShowOtp(false); setStudentOtp(Array(6).fill("")); }}>
                Back
              </Button>
              <Text type="secondary">Step {studentStep} of {studentSteps.length}</Text>
            </div>
            <Title level={3} className="student-theme-color"><UserOutlined className="student-theme-icon" style={{ marginRight: 8 }} />Student Registration</Title>
            <Text type="secondary">Fill the fields in each step. Progress and review page help you verify before final register.</Text>
            <div style={{ marginTop: 20, marginBottom: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <Text type="secondary">{studentSteps[studentStep - 1].title}</Text>
                <Text strong className="student-theme-color">{progress}%</Text>
              </div>
              <Progress percent={progress} showInfo={false} strokeColor="#3b82f6" />
            </div>
            <Form form={studentForm} layout="vertical" initialValues={studentData} onValuesChange={(_, allValues) => setStudentData({ ...studentData, ...allValues })}>
              {renderStudentFields()}
            </Form>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 24 }}>
              <Button icon={<ArrowLeftOutlined />} disabled={studentStep === 1} onClick={() => setStudentStep(studentStep - 1)}>Previous</Button>
              {studentStep < studentSteps.length && (
                <Button type="primary" icon={<ArrowRightOutlined />} onClick={onStudentNext} className="student-next-btn">Next</Button>
              )}
            </div>
          </Card>
        </Spin>
      </div>
    );
  }

  if (currentView === "teacher") {
    const progress = calcProgress(teacherStep, teacherSteps.length);
    return (
      <div className="form-container teacher-form-bg">
        <Spin spinning={loading} size="large">
          <Card className="form-card teacher-form-card" style={{ maxWidth: 700, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
              <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => { setCurrentView("landing"); setTeacherStep(1); teacherForm.resetFields(); setTeacherEmailVerified(false); setTeacherShowOtp(false); setTeacherOtp(Array(6).fill("")); }}>
                Back
              </Button>
              <Text type="secondary">Step {teacherStep} of {teacherSteps.length}</Text>
            </div>
            <Title level={3} className="teacher-theme-color"><TeamOutlined className="teacher-theme-icon" style={{ marginRight: 8 }} />Teacher Registration</Title>
            <Text type="secondary">Complete each step and review your teaching profile before final register.</Text>
            <div style={{ marginTop: 20, marginBottom: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <Text type="secondary">{teacherSteps[teacherStep - 1].title}</Text>
                <Text strong className="teacher-theme-color">{progress}%</Text>
              </div>
              <Progress percent={progress} showInfo={false} strokeColor="#10b981" />
            </div>
            <Form form={teacherForm} layout="vertical" initialValues={teacherData} onValuesChange={(_, allValues) => setTeacherData({ ...teacherData, ...allValues })}>
              {renderTeacherFields()}
            </Form>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 24 }}>
              <Button icon={<ArrowLeftOutlined />} disabled={teacherStep === 1} onClick={() => setTeacherStep(teacherStep - 1)}>Previous</Button>
              {teacherStep < teacherSteps.length && (
                <Button type="primary" icon={<ArrowRightOutlined />} onClick={onTeacherNext} className="teacher-next-btn">Next</Button>
              )}
            </div>
          </Card>
        </Spin>
      </div>
    );
  }

  if (currentView === "success") {
    const isStudent = role === "Student";
    return (
      <div className={`form-container ${isStudent ? "student-form-bg" : "teacher-form-bg"}`}>
        <Card className="form-card" style={{ maxWidth: 500, margin: "0 auto", textAlign: "center" }}>
          <CheckCircleOutlined style={{ fontSize: 64, color: isStudent ? "#3b82f6" : "#10b981", marginBottom: 24 }} />
          <Title level={3}>Registration Successful!</Title>
          <Paragraph>Welcome aboard! Your {isStudent ? "student" : "teacher"} account has been created successfully.</Paragraph>
          <Button type="primary" size="large" onClick={() => { setCurrentView("landing"); setStudentStep(1); setTeacherStep(1); studentForm.resetFields(); teacherForm.resetFields(); setStudentEmailVerified(false); setTeacherEmailVerified(false); setStudentShowOtp(false); setTeacherShowOtp(false); setStudentOtp(Array(6).fill("")); setTeacherOtp(Array(6).fill("")); }} className={isStudent ? "student-next-btn" : "teacher-next-btn"}>
            Back to Home
          </Button>
        </Card>
      </div>
    );
  }

  return null;
};

export default MultiRoleRegistration;
