/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Authoritative Schema Registry
 * Canonical inventory of all 114 tables defined in supabase_schema.sql
 * used for pre-switch database readiness and schema verification.
 */

export interface ExpectedTableSpec {
  name: string;
  domain: string;
  critical?: boolean;
}

export const EXPECTED_ERP_TABLES: readonly ExpectedTableSpec[] = [
  // Auth & Users
  { name: 'users', domain: 'Auth & Security', critical: true },
  { name: 'audit_logs', domain: 'Auth & Security', critical: true },

  // Basic Data & Master Setup
  { name: 'warehouses', domain: 'Basic Data', critical: true },
  { name: 'distributors', domain: 'Basic Data', critical: true },
  { name: 'customers', domain: 'Basic Data', critical: true },
  { name: 'products', domain: 'Basic Data', critical: true },
  { name: 'product_categories', domain: 'Basic Data', critical: true },
  { name: 'product_brands', domain: 'Basic Data' },
  { name: 'customer_categories', domain: 'Basic Data' },
  { name: 'raw_material_classifications', domain: 'Basic Data' },
  { name: 'raw_material_categories', domain: 'Basic Data' },
  { name: 'raw_materials', domain: 'Basic Data', critical: true },
  { name: 'org_hierarchy', domain: 'Basic Data', critical: true },
  { name: 'departments', domain: 'Basic Data', critical: true },
  { name: 'banks', domain: 'Basic Data' },
  { name: 'units_of_measurement', domain: 'Basic Data' },
  { name: 'field_force_reps', domain: 'Basic Data', critical: true },
  { name: 'offers_promotions', domain: 'Basic Data' },
  { name: 'office_locations', domain: 'Basic Data', critical: true },

  // Sales, Distribution & CRM
  { name: 'sales_orders', domain: 'Sales & CRM', critical: true },
  { name: 'retailer_orders', domain: 'Sales & CRM' },
  { name: 'retailer_order_items', domain: 'Sales & CRM' },
  { name: 'retailer_delivery_actions', domain: 'Sales & CRM' },
  { name: 'retailer_cancellations', domain: 'Sales & CRM' },
  { name: 'market_hierarchies', domain: 'Sales & CRM' },
  { name: 'crm_agreements', domain: 'Sales & CRM' },
  { name: 'visit_logs', domain: 'Sales & CRM' },
  { name: 'tada_claims', domain: 'Sales & CRM' },

  // Stock & Warehouse Inventory
  { name: 'stock_cid_receipts', domain: 'Inventory & Stock' },
  { name: 'stock_cid_receipt_items', domain: 'Inventory & Stock' },
  { name: 'stock_inventory', domain: 'Inventory & Stock', critical: true },
  { name: 'stock_opening_records', domain: 'Inventory & Stock' },
  { name: 'stock_issues', domain: 'Inventory & Stock' },
  { name: 'stock_issue_items', domain: 'Inventory & Stock' },
  { name: 'stock_primary_returns', domain: 'Inventory & Stock' },
  { name: 'stock_damage_returns', domain: 'Inventory & Stock' },
  { name: 'stock_transfers', domain: 'Inventory & Stock' },
  { name: 'stock_transfer_items', domain: 'Inventory & Stock' },
  { name: 'stock_adjustments', domain: 'Inventory & Stock' },
  { name: 'requisitions', domain: 'Inventory & Stock' },
  { name: 'requisition_items', domain: 'Inventory & Stock' },
  { name: 'stock_ledger', domain: 'Inventory & Stock' },

  // Procurement, Raw Materials & Manufacturing
  { name: 'suppliers', domain: 'Procurement & Manufacturing' },
  { name: 'import_orders', domain: 'Procurement & Manufacturing' },
  { name: 'import_order_items', domain: 'Procurement & Manufacturing' },
  { name: 'raw_material_receipts', domain: 'Procurement & Manufacturing' },
  { name: 'raw_material_receipt_items', domain: 'Procurement & Manufacturing' },
  { name: 'inventory_batches', domain: 'Procurement & Manufacturing', critical: true },
  { name: 'inventory_movements', domain: 'Procurement & Manufacturing' },
  { name: 'bill_of_materials', domain: 'Procurement & Manufacturing', critical: true },
  { name: 'bom_items', domain: 'Procurement & Manufacturing' },
  { name: 'production_orders', domain: 'Procurement & Manufacturing', critical: true },
  { name: 'material_issues', domain: 'Procurement & Manufacturing' },
  { name: 'material_issue_items', domain: 'Procurement & Manufacturing' },
  { name: 'production_consumption', domain: 'Procurement & Manufacturing' },
  { name: 'production_costs', domain: 'Procurement & Manufacturing' },
  { name: 'finished_goods_receipts', domain: 'Procurement & Manufacturing' },
  { name: 'optimum_statement', domain: 'Procurement & Manufacturing' },
  { name: 'expense_entries', domain: 'Procurement & Manufacturing' },
  { name: 'production_cost_allocations', domain: 'Procurement & Manufacturing' },

  // Installments, Collections & SMS
  { name: 'installment_plans', domain: 'Installments & Collections', critical: true },
  { name: 'installment_schedules', domain: 'Installments & Collections', critical: true },
  { name: 'installment_payments', domain: 'Installments & Collections' },
  { name: 'installment_payment_allocations', domain: 'Installments & Collections' },
  { name: 'installment_notifications', domain: 'Installments & Collections' },
  { name: 'installment_settings', domain: 'Installments & Collections' },
  { name: 'installment_audit_logs', domain: 'Installments & Collections' },
  { name: 'collection_assignments', domain: 'Installments & Collections' },
  { name: 'collection_followups', domain: 'Installments & Collections' },
  { name: 'collection_escalations', domain: 'Installments & Collections' },
  { name: 'sms_templates', domain: 'Installments & Collections' },
  { name: 'sms_automation_rules', domain: 'Installments & Collections' },
  { name: 'sms_logs', domain: 'Installments & Collections' },
  { name: 'sms_gateway_settings', domain: 'Installments & Collections' },

  // Warranty & Service
  { name: 'warranty_tickets', domain: 'Warranty & Service' },
  { name: 'battery_receiving_records', domain: 'Warranty & Service' },
  { name: 'technical_inspections', domain: 'Warranty & Service' },
  { name: 'service_job_cards', domain: 'Warranty & Service' },
  { name: 'service_invoices', domain: 'Warranty & Service' },
  { name: 'service_payments', domain: 'Warranty & Service' },
  { name: 'warranty_delivery_dispatches', domain: 'Warranty & Service' },

  // Payroll, HR, Attendance & Overtime
  { name: 'attendance_logs', domain: 'HR, Payroll & Overtime' },
  { name: 'employee_salary_structures', domain: 'HR, Payroll & Overtime', critical: true },
  { name: 'employee_attendances', domain: 'HR, Payroll & Overtime', critical: true },
  { name: 'attendance_rejected_attempts', domain: 'HR, Payroll & Overtime' },
  { name: 'employee_leaves', domain: 'HR, Payroll & Overtime' },
  { name: 'employee_advances_loans', domain: 'HR, Payroll & Overtime' },
  { name: 'employee_overtimes', domain: 'HR, Payroll & Overtime' },
  { name: 'employee_bonuses', domain: 'HR, Payroll & Overtime' },
  { name: 'monthly_payroll_runs', domain: 'HR, Payroll & Overtime' },
  { name: 'salary_payments', domain: 'HR, Payroll & Overtime' },
  { name: 'payroll_records', domain: 'HR, Payroll & Overtime' },
  { name: 'payroll_settings', domain: 'HR, Payroll & Overtime' },
  { name: 'overtime_policies', domain: 'HR, Payroll & Overtime', critical: true },
  { name: 'overtime_requests', domain: 'HR, Payroll & Overtime', critical: true },
  { name: 'overtime_attendances', domain: 'HR, Payroll & Overtime' },
  { name: 'overtime_batch_allocations', domain: 'HR, Payroll & Overtime' },
  { name: 'overtime_audit_logs', domain: 'HR, Payroll & Overtime' },

  // Finance, Cash/Bank & General Ledger
  { name: 'cash_book_entries', domain: 'Finance & Accounting' },
  { name: 'payments', domain: 'Finance & Accounting' },
  { name: 'cash_bank_accounts', domain: 'Finance & Accounting' },
  { name: 'cash_bank_transactions', domain: 'Finance & Accounting' },
  { name: 'opening_balance_configs', domain: 'Finance & Accounting' },
  { name: 'expense_categories', domain: 'Finance & Accounting' },
  { name: 'service_income_categories', domain: 'Finance & Accounting' },
  { name: 'chart_of_accounts', domain: 'Finance & Accounting', critical: true },
  { name: 'financial_years', domain: 'Finance & Accounting', critical: true },
  { name: 'accounting_periods', domain: 'Finance & Accounting' },
  { name: 'accounting_vouchers', domain: 'Finance & Accounting', critical: true },
  { name: 'accounting_voucher_lines', domain: 'Finance & Accounting' },
  { name: 'general_ledger_entries', domain: 'Finance & Accounting', critical: true },
  { name: 'account_opening_balances', domain: 'Finance & Accounting' },
  { name: 'accounting_settings', domain: 'Finance & Accounting' },
  { name: 'account_audit_logs', domain: 'Finance & Accounting' },
] as const;
