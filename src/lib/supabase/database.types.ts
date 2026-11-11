/**
 * Database types for the Rec Reports Supabase project (schema `public`).
 *
 * Produced by a one-off generator that reads information_schema.columns,
 * pg_proc, pg_enum and pg_constraint from a local Postgres built by
 * scripts/db/test-local.sh from supabase/migrations/. It is NOT output of the
 * Supabase CLI (`supabase gen types typescript`) and it was not produced by
 * @supabase/postgres-meta. Regenerate after every migration (the CLI command
 * against the migrated database is the source of truth once it is available),
 * and never edit by hand.
 */
export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type Database = {
  public: {
    Tables: {
      accounts: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          user_id: string
          disabled_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          user_id: string
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          user_id?: string
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "accounts_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "accounts_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      audit_log: {
        Row: {
          id: number
          occurred_at: string
          transaction_id: number
          organization_id: string | null
          location_id: string | null
          actor_user_id: string | null
          actor_person_id: string | null
          actor_role: string
          action: string
          table_schema: string
          table_name: string
          row_id: string | null
          old_row: Json | null
          new_row: Json | null
          changed_columns: string[] | null
        }
        Insert: {
          id: number
          occurred_at?: string
          transaction_id?: number
          organization_id?: string | null
          location_id?: string | null
          actor_user_id?: string | null
          actor_person_id?: string | null
          actor_role: string
          action: string
          table_schema: string
          table_name: string
          row_id?: string | null
          old_row?: Json | null
          new_row?: Json | null
          changed_columns?: string[] | null
        }
        Update: {
          id?: number
          occurred_at?: string
          transaction_id?: number
          organization_id?: string | null
          location_id?: string | null
          actor_user_id?: string | null
          actor_person_id?: string | null
          actor_role?: string
          action?: string
          table_schema?: string
          table_name?: string
          row_id?: string | null
          old_row?: Json | null
          new_row?: Json | null
          changed_columns?: string[] | null
        }
        Relationships: [
        ]
      }
      job_titles: {
        Row: {
          id: string
          organization_id: string
          name: string
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "job_titles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      locations: {
        Row: {
          id: string
          organization_id: string
          name: string
          code: string | null
          timezone: string
          address: string | null
          phone: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          code?: string | null
          timezone: string
          address?: string | null
          phone?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          code?: string | null
          timezone?: string
          address?: string | null
          phone?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "locations_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      modules: {
        Row: {
          key: string
          name: string
          sort_order: number
          created_at: string
          updated_at: string
        }
        Insert: {
          key: string
          name: string
          sort_order?: number
          created_at?: string
          updated_at?: string
        }
        Update: {
          key?: string
          name?: string
          sort_order?: number
          created_at?: string
          updated_at?: string
        }
        Relationships: [
        ]
      }
      organization_settings: {
        Row: {
          id: string
          organization_id: string
          default_timezone: string
          week_starts_on: number
          settings: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          default_timezone?: string
          week_starts_on?: number
          settings?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          default_timezone?: string
          week_starts_on?: number
          settings?: Json
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_settings_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      organizations: {
        Row: {
          id: string
          name: string
          slug: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          slug: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          slug?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
        ]
      }
      people: {
        Row: {
          id: string
          organization_id: string
          first_name: string
          last_name: string
          preferred_name: string | null
          email: string | null
          phone: string | null
          employee_number: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          first_name: string
          last_name: string
          preferred_name?: string | null
          email?: string | null
          phone?: string | null
          employee_number?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          first_name?: string
          last_name?: string
          preferred_name?: string | null
          email?: string | null
          phone?: string | null
          employee_number?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "people_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      person_job_titles: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          job_title_id: string
          location_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          job_title_id: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          job_title_id?: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "person_job_titles_job_title_id_organization_id_fkey"
            columns: ["job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "person_job_titles_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "person_job_titles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "person_job_titles_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      platform_admins: {
        Row: {
          user_id: string
          note: string | null
          created_at: string
        }
        Insert: {
          user_id: string
          note?: string | null
          created_at?: string
        }
        Update: {
          user_id?: string
          note?: string | null
          created_at?: string
        }
        Relationships: [
        ]
      }
      role_assignments: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          role_id: string
          location_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          role_id: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          role_id?: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "role_assignments_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "role_assignments_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "role_assignments_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "role_assignments_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
        ]
      }
      role_default_permissions: {
        Row: {
          id: string
          organization_id: string | null
          role_id: string
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id?: string | null
          role_id: string
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string | null
          role_id?: string
          module_key?: string
          level?: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "role_default_permissions_module_key_fkey"
            columns: ["module_key"]
            isOneToOne: false
            referencedRelation: "modules"
            referencedColumns: ["key"]
          },
          {
            foreignKeyName: "role_default_permissions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "role_default_permissions_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
        ]
      }
      roles: {
        Row: {
          id: string
          organization_id: string | null
          key: string
          name: string
          description: string | null
          rank: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id?: string | null
          key: string
          name: string
          description?: string | null
          rank: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string | null
          key?: string
          name?: string
          description?: string | null
          rank?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "roles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      space_closures: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_id: string | null
          starts_at: string
          ends_at: string
          reason: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_id?: string | null
          starts_at: string
          ends_at: string
          reason?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_id?: string | null
          starts_at?: string
          ends_at?: string
          reason?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_closures_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "space_closures_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "space_closures_space_id_organization_id_location_id_fkey"
            columns: ["space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      space_hours: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_id: string
          day_of_week: number
          opens_at: string
          closes_at: string
          effective_from: string | null
          effective_to: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_id: string
          day_of_week: number
          opens_at: string
          closes_at: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_id?: string
          day_of_week?: number
          opens_at?: string
          closes_at?: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_hours_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "space_hours_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "space_hours_space_id_organization_id_location_id_fkey"
            columns: ["space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      space_kinds: {
        Row: {
          id: string
          organization_id: string
          key: string
          name: string
          sort_order: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          key: string
          name: string
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          key?: string
          name?: string
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_kinds_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      spaces: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_kind_id: string
          parent_space_id: string | null
          name: string
          description: string | null
          capacity: number | null
          sort_order: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_kind_id: string
          parent_space_id?: string | null
          name: string
          description?: string | null
          capacity?: number | null
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_kind_id?: string
          parent_space_id?: string | null
          name?: string
          description?: string | null
          capacity?: number | null
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "spaces_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "spaces_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "spaces_parent_space_id_organization_id_location_id_fkey"
            columns: ["parent_space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
          {
            foreignKeyName: "spaces_space_kind_id_organization_id_fkey"
            columns: ["space_kind_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "space_kinds"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      user_permissions: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          location_id: string | null
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          location_id?: string | null
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          location_id?: string | null
          module_key?: string
          level?: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "user_permissions_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "user_permissions_module_key_fkey"
            columns: ["module_key"]
            isOneToOne: false
            referencedRelation: "modules"
            referencedColumns: ["key"]
          },
          {
            foreignKeyName: "user_permissions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "user_permissions_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      actor_rank: {
        Args: { p_organization_id: string; p_location_id: string | null }
        Returns: number
      }
      auth_location_ids: {
        Args: never
        Returns: string[]
      }
      auth_org_ids: {
        Args: never
        Returns: string[]
      }
      current_person_id: {
        Args: { p_organization_id: string }
        Returns: string
      }
      effective_permission: {
        Args: { p_organization_id: string; p_location_id: string | null; p_module_key: string }
        Returns: Database["public"]["Enums"]["permission_level"]
      }
      has_permission: {
        Args: {
          p_organization_id: string
          p_location_id: string | null
          p_module_key: string
          p_min_level: Database["public"]["Enums"]["permission_level"]
        }
        Returns: boolean
      }
      has_role: {
        Args: { p_organization_id: string; p_location_id: string | null; p_role_key: string }
        Returns: boolean
      }
      is_platform_admin: {
        Args: never
        Returns: boolean
      }
      can_manage_person_account: {
        Args: { p_organization_id: string; p_person_id: string }
        Returns: boolean
      }
      consume_rate_limit: {
        Args: { p_bucket: string; p_key: string; p_max: number; p_window_seconds: number }
        Returns: boolean
      }
      create_person_with_assignment: {
        Args: {
          p_organization_id: string
          p_first_name: string
          p_last_name: string
          p_role_id: string
          p_location_id: string | null
          p_preferred_name?: string | null
          p_email?: string | null
          p_phone?: string | null
          p_employee_number?: string | null
        }
        Returns: string
      }
      person_effective_permission: {
        Args: {
          p_organization_id: string
          p_person_id: string
          p_location_id: string | null
          p_module_key: string
        }
        Returns: Database["public"]["Enums"]["permission_level"]
      }
      replace_role_assignment: {
        Args: { p_assignment_id: string; p_role_id: string; p_location_id: string | null }
        Returns: string
      }
      session_needs_mfa: {
        Args: never
        Returns: boolean
      }
      update_own_profile: {
        Args: { p_organization_id: string; p_preferred_name: string | null; p_phone: string | null }
        Returns: string
      }
    }
    Enums: {
      permission_level: "none" | "view" | "edit" | "admin"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DefaultSchema = Database["public"]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof Database },
  EnumName extends DefaultSchemaEnumNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof Database },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
  ? Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      permission_level: ["none", "view", "edit", "admin"],
    },
  },
} as const
